#coding: utf-8
import re
import PyV8
import ujson as json
import requests
from time import sleep
from bs4 import BeautifulSoup

try:
    import cPickle as pickle
except ImportError:
    import pickle

class SpamHaus:
    def __init__(self, session_file=None):
        self.url = "https://www.spamhaus.org"
        self.session_file = session_file or "session.data"
        session = self.__load_session()            
        self.session = session or requests.session()
        
    def __del__(self):
        if self.session:
            self.__save_session(self.session)               
        
    def __load_session(self):
        session = None
        try:            
            with open(self.session_file, 'rb') as fp:
                session = pickle.load(fp)               
        except IOError:
            pass
        return session        
   
    def __save_session(self, session):
        try:
            with open(self.session_file, 'wb') as fp:
                pickle.dump(session, fp)               
        except IOError:
            pass
        
    def __headers(self, ip):
        return {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',          
            'Referer': 'https://www.spamhaus.org/query/ip/%s' %ip,                   
        }
        
    def exec_script_func(self, script_func):
        ctxt = PyV8.JSContext()       
        ctxt.enter()              
        func = ctxt.eval(script_func)       
        return func()       
    
    def __get_script_func(self, html):
        match_parseInt = re.search(r'parseInt\(([^,]+),\s*\d+\)', html)
        if match_parseInt is None:
            return
        parseInt = match_parseInt.group()
        parseInt_arg1 = match_parseInt.group(1)
        match_calc_script = re.findall(r'(%s[+\-\*=]+[^;]+;)[\1]{0,}' %parseInt_arg1, html)
        if match_calc_script is None:
            return
        calc_script = "".join(match_calc_script)
        match_var = re.search(r'%s={[^;]+};'%parseInt_arg1.split('.')[0], html)
        if match_var is None:
            return
        script_var = match_var.group()        
        return '''(function(){var %s;%s;return %s+16;})''' %(script_var, calc_script, parseInt)     
    
    def __get_cdata(self, html):  
        soup = BeautifulSoup(html, 'html.parser')               
        form_tag = soup.find('form', attrs={'id':'challenge-form', 'method':'get'})
        if form_tag is None:
            return
        jsch1_vc_tag = form_tag.find('input', attrs={'type':'hidden', 'name':'jschl_vc'})
        pass_tag = form_tag.find('input', attrs={'type':'hidden', 'name':'pass'}) 
        if not jsch1_vc_tag or not pass_tag:
            return
        jschl_value = jsch1_vc_tag['value']
        pass_value = pass_tag['value']
        match_cdata = re.search(r'//<!\[CDATA\[(.*?)//\]\]>', html, re.S)    
        if match_cdata is None:
            return       
        cdata = match_cdata.group()       
        script_func = self.__get_script_func(cdata)
        answer_value = self.exec_script_func(script_func)        
        return  jschl_value, pass_value, answer_value   
    
    def get(self, ip):
        url = "%s/query/ip/%s" %(self.url, ip)
        resp = self.session.get(url, headers=self.__headers(ip))         
           
        if(resp.status_code == 503):
            print 'please sleep 5 seconds....'
            sleep(5)            
            jschl_vc, jschl_pass, jschl_answer = self.__get_cdata(resp.text)         
            params = {
                'jschl_vc': jschl_vc,
                'pass': jschl_pass,
                'jschl_answer': jschl_answer
                }
            cdata_url = "%s/cdn-cgi/l/chk_jschl" %self.url           
            jschl_resp = self.session.get(cdata_url, params=params, headers=self.__headers(ip)) 
            if jschl_resp.status_code == 200:
                self.__save_session(self.session)   
                                        
        if resp.status_code != 200:                              
            resp = self.session.get(url, headers=self.__headers(ip))          
        print resp.text             
        
if __name__ == '__main__':
    spam = SpamHaus()      
    spam.get('221.232.129.89')    
   
   
   
  
   
        
    
    
