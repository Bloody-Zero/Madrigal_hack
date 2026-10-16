"""Local API and background task runner."""
import copy
import secrets
import threading
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from .common import LabError, Cancelled
from .capture import MAX_CAPTURE, version
from .project import Project
from .rules import PROFILES
from .streams import references


def create_app(root):
    project = Project(root)
    project.acquire()
    app = FastAPI(title='Лаборатория протоколов', docs_url=None, redoc_url=None)
    app.state.project = project
    token = secrets.token_urlsafe(32)
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='lab')
    jobs, jobs_lock = {}, threading.Lock()
    static = Path(__file__).parent/'static'

    def shutdown():
        with jobs_lock:
            for item in jobs.values():
                item['event'].set()
        executor.shutdown(wait=True,cancel_futures=True)
        project.release()
    app.add_event_handler('shutdown',shutdown)

    @app.middleware('http')
    async def local_only(request, call_next):
        host = request.url.hostname
        if host not in ('localhost','127.0.0.1','testserver'):
            return JSONResponse({'error':'Только локальный доступ'},status_code=403)
        if request.method not in ('GET','HEAD') and request.headers.get('x-lab-token') != token:
            return JSONResponse({'error':'Откройте интерфейс приложения; токен сеанса недействителен'},status_code=403)
        response = await call_next(request)
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['Cache-Control']='no-store'
        response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
        return response

    @app.exception_handler(LabError)
    async def lab_error(request, exc):
        return JSONResponse({'error':str(exc)},status_code=400)

    def submit(operation):
        jid, event = uuid.uuid4().hex, threading.Event()
        with jobs_lock:
            if any(j['status'] in ('queued','running') for j in jobs.values()):
                raise LabError('Дождитесь текущей задачи или отмените её')
            jobs[jid] = {'id':jid,'status':'queued','progress':0,'stage':'В очереди','event':event}

        def progress(value, stage):
            with jobs_lock:
                jobs[jid].update(progress=value,stage=stage)

        def work():
            with jobs_lock:
                jobs[jid]['status']='running'
            try:
                result = operation(event, progress)
                with jobs_lock:
                    jobs[jid].update(status='done',result=result,stage='Готово')
            except Exception as e:
                if not isinstance(e,LabError):
                    traceback.print_exc()
                with jobs_lock:
                    jobs[jid].update(status='cancelled' if isinstance(e,Cancelled) else 'error',error=str(e))
        executor.submit(work)
        return {'job_id':jid}

    @app.get('/')
    def index():
        return FileResponse(static/'index.html')

    @app.get('/api/bootstrap')
    def bootstrap():
        try:
            tshark = version()
        except Exception as e:
            tshark = str(e)
        return {'token':token,'profiles':PROFILES,'tshark':tshark,'max_capture':MAX_CAPTURE}

    @app.get('/api/project')
    def state():
        return project.summary()

    @app.get('/api/stream/{sid}')
    def stream(sid:str, start:int=0, length:int=512):
        s = project.stream(sid)
        if not s:
            raise LabError('Поток не найден')
        start=max(0,min(start,s['length'])); length=max(1,min(length,4096))
        end=min(start+length,s['length'])
        data={k:v for k,v in s.items() if k not in ('hex','known','conflicts','provenance')}
        data.update(start=start,end=end,hex=s['hex'][start*2:end*2],
            known=s['known'][start*2:end*2],conflicts=s['conflicts'][start*2:end*2],
            references=references(s,start,end))
        return data

    @app.get('/api/packet/{source_id}/{frame}')
    def packet(source_id:str,frame:int):
        p=next((p for p in project.source_data(source_id)['capture']['packets'] if p['frame']==frame),None)
        if p is None:
            raise LabError('Пакет не найден')
        return p

    @app.get('/api/diagnostics/{source_id}')
    def diagnostics(source_id:str):
        c=project.source_data(source_id)['capture']
        return {'diagnostics':c['diagnostics'],'checksum_policy':c['checksum_policy'],
            'checksums':[{'frame':p['frame'],'status':p['checksum']} for p in c['packets'] if p['checksum'] not in ('1','')],
            'truncated':[p['frame'] for p in c['packets'] if p['captured_length']<p['wire_length']]}

    @app.get('/api/search/{sid}')
    def search(sid:str,hex:str,start:int=0):
        s=project.stream(sid)
        if not s:
            raise LabError('Поток не найден')
        try:
            needle=bytes.fromhex(hex)
        except ValueError:
            raise LabError('Поиск: задайте байты HEX, например AA 55')
        if not needle or len(needle)>4096:
            raise LabError('Поиск: от 1 до 4096 байтов')
        data=bytes.fromhex(s['hex']);known=bytes.fromhex(s['known']);conflict=bytes.fromhex(s['conflicts'])
        at=max(0,start)
        while True:
            at=data.find(needle,at)
            if at<0:
                return {'offset':None}
            end=at+len(needle)
            if 0 not in known[at:end] and 1 not in conflict[at:end]:
                return {'offset':at}
            at+=1

    @app.get('/api/actions/{aid}/locate')
    def locate_action(aid:str):
        action=next((a for a in project.data['actions'] if a['id']==aid),None)
        if not action:
            raise LabError('Действие не найдено')
        choices=[(abs(float(p['time'])-action['capture_time']),s,p)
                 for s in project.source_data(action['source_id'])['streams']
                 for p in s['provenance'] if p['end']>p['start']]
        if not choices:
            raise LabError('Нет доступных данных обмена')
        delta,s,p=min(choices,key=lambda x:x[0])
        return {'stream_id':s['id'],'start':p['start'],'end':p['end'],'delta_seconds':delta}

    async def bounded_body(request, limit):
        body=bytearray()
        async for chunk in request.stream():
            if len(body)+len(chunk)>limit:
                raise LabError('Превышен допустимый размер запроса')
            body.extend(chunk)
        return bytes(body)

    async def object_body(request):
        import json
        try:
            data=json.loads(await bounded_body(request,1024*1024))
        except (ValueError,UnicodeError):
            raise LabError('Некорректный JSON запроса')
        if not isinstance(data,dict):
            raise LabError('Ожидается JSON-объект')
        return data

    @app.post('/api/import')
    async def import_file(request:Request, name:str):
        raw=await bounded_body(request,MAX_CAPTURE)
        return submit(lambda cancel,progress:project.import_capture(name,raw,cancel,progress))

    @app.post('/api/rule')
    async def rule(request:Request):
        import json
        try:
            data=json.loads(await bounded_body(request,1024*1024))
        except (ValueError,UnicodeError):
            raise LabError('Некорректный JSON правил')
        project.set_rule(data)
        return {'saved':True}

    @app.post('/api/check')
    async def check(request:Request):
        data=await object_body(request)
        ids=data.get('stream_ids')
        if not isinstance(ids,list) or not all(isinstance(x,str) for x in ids):
            raise LabError('Нужен список stream_ids')
        return submit(lambda cancel,progress:project.run(ids,cancel,progress))

    @app.get('/api/jobs/{jid}')
    def job(jid:str):
        with jobs_lock:
            if jid not in jobs:
                raise LabError('Задача не найдена')
            return {k:v for k,v in jobs[jid].items() if k!='event'}

    @app.post('/api/jobs/{jid}/cancel')
    def cancel(jid:str):
        with jobs_lock:
            if jid not in jobs:
                raise LabError('Задача не найдена')
            jobs[jid]['event'].set()
        return {'requested':True}

    @app.get('/api/runs/{rid}')
    def run(rid:str,offset:int=0,limit:int=100,status:str='all'):
        r=project.run_data(rid)
        rows=[dict(row,index=i) for i,row in enumerate(r['rows']) if status=='all' or row['status']==status]
        r['filtered_count']=len(rows)
        r['rows']=rows[max(0,offset):max(0,offset)+max(1,min(limit,500))]
        r['stale']=r['rule_hash']!=__import__('lab.common',fromlist=['digest']).digest(project.data['rule'])
        return r

    @app.post('/api/notes')
    async def notes(request:Request):
        return project.add_note(await object_body(request))

    @app.post('/api/actions')
    async def actions(request:Request):
        d=await object_body(request)
        if not isinstance(d.get('csv'),str):
            raise LabError('Нужен текст CSV')
        return {'imported':project.import_actions(d['csv'],d.get('clock_offset',0))}

    @app.get('/api/rule/download')
    def rule_download():
        return JSONResponse(project.data['rule'],headers={'Content-Disposition':'attachment; filename=rules.json'})

    @app.get('/api/runs/{rid}/download')
    def run_download(rid:str):
        return JSONResponse(project.run_data(rid),headers={'Content-Disposition':'attachment; filename=results.json'})

    @app.get('/api/runs/{rid}/report')
    def report(rid:str):
        return HTMLResponse(project.report(rid))

    @app.get('/api/export')
    def export():
        return Response(project.export(),media_type='application/zip',headers={'Content-Disposition':'attachment; filename=research-project.zip'})

    app.mount('/static',StaticFiles(directory=static),name='static')
    return app
