"""Real browser workflow. Requires requirements-dev and playwright install chromium."""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright, expect


def main():
    root=Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as temp:
        with socket.socket() as s:
            s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        proc=subprocess.Popen([sys.executable,'launcher.py','--project',str(Path(temp)/'research'),'--port',str(port),'--no-browser'],cwd=root,stdout=subprocess.DEVNULL)
        try:
            for _ in range(100):
                try:
                    urllib.request.urlopen(f'http://127.0.0.1:{port}',timeout=.2).close();break
                except OSError:time.sleep(.1)
            with sync_playwright() as p:
                browser=p.chromium.launch(headless=True,args=['--no-sandbox'])
                page=browser.new_page(viewport={'width':1440,'height':1000})
                errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
                page.goto(f'http://127.0.0.1:{port}')
                expect(page.locator('#saveState')).to_have_text('Сохранено')
                for name in ('training.pcap','additional.pcap'):
                    page.locator('#captureFile').set_input_files(root/'examples'/name)
                    expect(page.locator('.source-name',has_text=name)).to_be_visible(timeout=15000)
                expect(page.locator('#hex')).to_contain_text('aa')
                page.locator('#selectAll').click()
                expect(page.locator('#selectedCount')).to_have_text('2')
                page.locator('#check').click()
                expect(page.locator('#resultRows tr')).to_have_count(5,timeout=15000)
                expect(page.locator('#runSummary')).to_contain_text('"ok":5')
                page.locator('.field-result').first.click()
                page.locator('#noteText').fill('Гипотеза: AA55 — маркер начала; проверено на двух записях')
                page.locator('#addNote').click()
                page.locator('nav [data-tab=journal]').click()
                expect(page.locator('#notes')).to_contain_text('маркер начала')
                page.locator('#actionsFile').set_input_files(root/'examples/actions.csv')
                page.locator('#importActions').click()
                expect(page.locator('#actions .journal-entry')).to_have_count(4)
                page.locator('.action-open').first.click()
                expect(page.locator('#packetDetails')).to_contain_text('Ближайший по времени')
                page.locator('nav [data-tab=rules]').click()
                page.locator('#lengthWidth').select_option('1')
                expect(page.locator('#saveState')).to_have_text('Сохранено',timeout=5000)
                page.locator('nav [data-tab=results]').click()
                page.locator('#check2').click()
                expect(page.locator('#runSummary')).to_contain_text('violation',timeout=15000)
                page.locator('nav [data-tab=rules]').click()
                page.locator('#lengthWidth').select_option('2')
                expect(page.locator('#saveState')).to_have_text('Сохранено')
                page.locator('nav [data-tab=exchange]').click()
                page.locator('#searchHex').fill('AA 55')
                page.locator('#search').click()
                page.locator('nav [data-tab=compare]').click()
                page.locator('#compareGo').click()
                expect(page.locator('#compareSummary')).to_contain_text('Различающихся позиций')
                page.locator('nav [data-tab=exchange]').click()
                if os.environ.get('LAB_QA_SCREENSHOT'):
                    page.screenshot(path=os.environ['LAB_QA_SCREENSHOT'],full_page=True)
                page.reload();expect(page.locator('#saveState')).to_have_text('Сохранено')
                expect(page.locator('.source-name')).to_have_count(2)
                page.locator('nav [data-tab=journal]').click()
                expect(page.locator('#notes')).to_contain_text('маркер начала')
                assert not errors,errors
                assert not page.locator('#error').is_visible(),page.locator('#error').text_content()
                browser.close()
                print(json.dumps({'browser':'Chromium','workflow':'PASS','page_errors':errors,
                    'checks':['upload','TCP view','corpus','rules','counterexample','notes','actions','comparison','reload']},ensure_ascii=False,indent=2))
        finally:
            proc.terminate()
            try:proc.wait(timeout=10)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()


if __name__=='__main__':main()
