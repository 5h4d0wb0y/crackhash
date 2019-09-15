# -*- coding: utf -*-

import re
import json
from selenium.webdriver.common.keys import Keys


def myaddr(browser, hashvalue, hashtype):
    browser.driver.get('http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php')
    search_input = browser.driver.find_element_by_name('md5')
    search_input.click()
    search_input.send_keys(hashvalue)

    search_input.send_keys(Keys.RETURN)
    #form = browser.driver.find_element_by_name('f1')
    #form.submit1()
    #button = browser.driver.find_element_by_xpath("//input[@title='go >>>']")
    #button.click()
    browser.wait_page_has_loaded()
    elem = browser.wait_until_element_exists('xpath', '//div[@class="search_result"]')
    html = elem.get_attribute('innerHTML')
    match = re.findall(r"Hashed string</span>: (.*)</div>", html)[0]
    if match:
        return match
    else:
        return False

def nitrxgen(browser, hashvalue, hashtype):
    browser.driver.get("https://www.nitrxgen.net/md5db/" + hashvalue)
    clean = re.compile('<.*?>')
    match = re.sub(clean, '', browser.driver.page_source)
    if match:
        return match
    else:
        return False

def md5decrypt(browser, hashvalue, hashtype):
    if (hashtype == 'md5') or (hashtype == 'ldap_md5'):
        browser.driver.get("https://md5decrypt.net/")
    elif hashtype == 'ldap_sha1':
        browser.driver.get("https://md5decrypt.net/Sha1")
    else:
        browser.driver.get("https://md5decrypt.net/%s" % hashtype.capitalize())

    browser.driver.find_element_by_id("hash_input").send_keys(hashvalue)
    browser.driver.find_element_by_name("decrypt").click()
    browser.wait_page_has_loaded()
    match = browser.wait_until_element_exists('xpath', '//*[@id="answer"]/b')
    if match.text:
        return match.text
    else:
        return False

def hashcrack(browser, hashvalue, hashtype):
    browser.driver.get("https://hashcrack.com/lookup.js?hash=" + hashvalue)
    clean = re.compile('<.*?>')
    res = re.sub(clean, '', browser.driver.page_source)
    match = json.loads(res)
    if match['success'] and match['plain']:
        return match['plain']
    else:
        return False

def hashtoolkit(browser, hashvalue, hashtype):
    browser.driver.get("https://hashtoolkit.com/reverse-hash/?hash=" + hashvalue)
    match = browser.driver.find_element_by_xpath("//span[@title='decrypted " + hashtype + " hash']").text
    if match:
        return match
    else:
        return False

def md5hashing(browser, hashvalue, hashtype):
    if 'rmd' in hashtype:
        ht = 'ripemd' + str(int(''.join(filter(str.isdigit, hashtype))))
        browser.driver.get("https://md5hashing.net/hash/" + ht + "/" + str(hashvalue))
    else:
        browser.driver.get("https://md5hashing.net/hash/" + hashtype + "/" + str(hashvalue))
    elem = browser.wait_until_element_exists('id', 'decodedValue')
    match = elem.text
    if match:
        return match
    else:
        return False

def hashkiller(browser, hashvalue, hashtype):
    if hashtype == 'md5':
        browser.driver.get("https://hashkiller.co.uk/Cracker/MD5")
    elif hashtype == 'sha1':
        browser.driver.get("https://hashkiller.co.uk/Cracker/SHA1")
    elif hashtype == 'sha256':
        browser.driver.get("https://hashkiller.co.uk/Cracker/SHA256")
    elif hashtype == 'sha512':
        browser.driver.get("https://hashkiller.co.uk/Cracker/SHA512")
    elif hashtype == 'ntlm':
        browser.driver.get("https://hashkiller.co.uk/Cracker/NTLM")
    elif hashtype == 'mysql':
        browser.driver.get("https://hashkiller.co.uk/Cracker/MySQL5")

    browser.driver.find_element_by_id('txtHashList').send_keys(hashvalue)
    browser.driver.find_element_by_xpath('//*[@id="btnCrack"]').click()

    browser.wait_page_has_loaded()
    elem = browser.wait_until_element_exists('xpath', '//*[@id="pass_0"]')
    match = elem.text
    if match:
        return match
    else:
        return False

def passworddecrypt(browser, hashvalue, hashtype):
    browser.driver.get("http://password-decrypt.com/" + hashtype + ".cgi")
    if hashtype == 'cisco':
        browser.driver.find_element_by_name('cisco_password').send_keys(hashvalue)
    elif hashtype == 'juniper':
        browser.driver.find_element_by_name('juniper_password').send_keys(hashvalue)
    browser.driver.find_element_by_css_selector("input:nth-child(4)").click()
    res = browser.wait_until_element_exists('css', 'b')
    match = res.text
    if match:
        return match
    else:
        return False

def m00nie(browser, hashvalue, hashtype):
    if hashtype == 'cisco':
        browser.driver.get("https://www.m00nie.com/type-7-password-tool/")
    elif hashtype == 'juniper':
        browser.driver.get("https://www.m00nie.com/juniper-type-9-password-tool/")
    browser.driver.switch_to.frame(0)
    browser.driver.find_element_by_css_selector("form > input:nth-child(2)").click()
    browser.driver.find_element_by_name("string").send_keys(hashvalue)

    browser.driver.find_element_by_name("string").send_keys(Keys.RETURN)
    #browser.driver.find_element_by_css_selector("input:nth-child(3)").click()

    browser.wait_page_has_loaded()
    elem = browser.driver.find_element_by_id('result').text
    match = elem.split(' ')[-1]
    if match:
        return match
    else:
        return False

def firewallruletest(browser, hashvalue, hashtype):
    browser.driver.get("http://firewallruletest.com/cisco/type7dec/?type7pass=" + hashvalue)
    clean = re.compile('<.*?>')
    match = re.sub(clean, '', browser.driver.page_source)
    if match:
        return match
    else:
        return False

def ifm(browser, hashvalue, hashtype):
    browser.driver.get("http://www.ifm.net.nz/cookbooks/passwordcracker.html")
    browser.driver.find_element_by_name("crypttext").send_keys(hashvalue)
    browser.driver.find_element_by_xpath("//input[@value='Crack Password']").click()
    match = browser.driver.find_element_by_name('plaintext').get_attribute('value')
    if match:
        return match
    else:
        return False

def ibeast(browser, hashvalue, hashtype):
    browser.driver.get("http://ibeast.com/tools/CiscoPassword/index.asp")
    browser.driver.find_element_by_name('txtPassword').send_keys(hashvalue)
    browser.driver.find_element_by_id('submit1').click()
    elem = browser.driver.find_element_by_xpath('/html/body/center/font[3]')
    html = elem.get_attribute('innerHTML')
    #match = re.findall(r"Your password is (.*?)<br>", html)
    match = html.split(' ')[3].split('<br>')[0]
    if match:
        return match
    else:
        return False

def cmd5(browser, hashvalue, hashtype):
    browser.driver.get("https://www.cmd5.org/")
    #select = browser.select_dropdown_by('id', 'ctl00_ContentPlaceHolder1_InputHashType')
    #select.select_by_visible_text('auto')
    cont = browser.driver.find_element_by_id('ctl00_ContentPlaceHolder1_TextBoxInput')
    cont.send_keys(hashvalue)
    #browser.driver.find_element_by_id('ctl00_ContentPlaceHolder1_Button1').click()
    cont.send_keys(Keys.RETURN)

    browser.wait_page_has_loaded()
    match = browser.driver.find_element_by_xpath('//*[@id="LabelAnswer"]').text
    if 'Not Found' in match:
        return False
    else:
        return match

def it64(browser, hashvalue, hashtype):
    browser.driver.get("http://rainbowtables.it64.com/p3.php")
    #browser.driver.switch_to.frame(1)
    #print(browser.driver.page_source)
    browser.driver.find_element_by_xpath('//*[@name="hashe"]').send_keys(hashvalue)
    browser.driver.find_element_by_xpath('//*[@name="ifik"]').click()
    
    browser.driver.switch_to_window(browser.driver.window_handles[1])

    if len(hashvalue) == 16:
        #elem = browser.wait_until_element_exists('xpath', '//tr[2]/td[3]')
        elem = browser.wait_until_element_exists('css', 'tr:nth-child(2) > td:nth-child(3)')
        match = elem.text
    elif len(hashvalue) == 32:
        elem1 = browser.wait_until_element_exists('css', 'tr:nth-child(2) > td:nth-child(3)')
        elem2 = browser.wait_until_element_exists('css', 'tr:nth-child(3) > td:nth-child(3)')
        match = elem1.text + elem2.text
        match = match.replace(" ", "")
    
    # Close result tab
    browser.driver.close()
    browser.driver.switch_to_window(browser.driver.window_handles[0])

    if match:
        return match
    else:
        return False