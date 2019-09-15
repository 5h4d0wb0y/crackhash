import base64
from crackhash import scraper
from crackhash import browser

browser = browser.Browser()
browser.start()


hash = 'E52CAC67419A9A224A3B108F3FA6CB6D'
algo = 'lm'
res = scraper.it64(browser, hash, algo)
print(res)

hash = '5f4dcc3b5aa765d61d8327deb882cf99'
algo = 'md5'
res = scraper.cmd5(browser, hash, algo)
print(res)