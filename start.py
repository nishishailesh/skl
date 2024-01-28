import sys, logging, os, datetime
import config, time
logging.basicConfig(filename=config.log_filename,level=logging.DEBUG,force=True)  

import common_modules.common_mysql as myassql
import importlib,bcrypt
import urllib.parse #simple urllib do not work. it consume a lot of memory. so, setup to import perticular module
import secrets
import config

import string
import random

sys.path.append(config.mysql_secret_file_location)
astm_var = importlib.import_module(config.mysql_secret_module, package=None)

header1='''<link  rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/css/bootstrap.min.css" 
                  integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" 
                  crossorigin="anonymous">'''


def do_work(environ):
    #post is from file like object. and no seek to 0. os read once and make available where ever required
    post=get_post(environ)
    if(b'action' not in post):
      ret=[login()]
    else:
      public_key=verify_user(post)
      if(public_key!=False):
        ret=[
              #b'login is successul',
              #echo_post(post),
              #public_key,
              open_new_window(post[b'username'],public_key)
            ]
      else:
        ret=[
              b'login is not successful',
              login()
              #echo_post(post)
            ]
    return ret
##########################Work function#########################3
def login():
  form='''<html><head>'''+header1+'''</head><body>
  <form method=post>
  <input class=text-danger type=text name=username>
  <input type=password name=password>
  <input type=submit name=action value=login>
  <form>
  </body>
  </html>'''
  return form.encode("UTF-8")

def echo_post(post):
    return '<pre>{}</pre>'.format(post).encode("UTF-8")

def open_new_window(username,public_key):
  form='''
  <form method=post target=_blank>
    <button type=submit name=action value=open_new_window>+</button>
    <input type=hidden name=public_key value=\''''+public_key.decode("UTF-8")+'''\'>
    <input type=hidden name=username value=\''''+username.decode("UTF-8")+ '''\'>
  </form>
  '''
  return form.encode("UTF-8")
  

#########################Support function#########################    
def get_post(environ):
  #environ['wsgi.input'] is file like object
  post={}
  try:
    request_body_size = int(environ.get('CONTENT_LENGTH', 0))
    request_body = environ['wsgi.input'].read(request_body_size)
    logging.debug('===POST====')
    logging.debug('request_body={}'.format(request_body))
    if(len(request_body)>0):
      for attr_value_pair in request_body.decode().split("&"):
        pair=attr_value_pair.split("=")
        logging.debug('attr_value_pair={}'.format(pair))
        post[urllib.parse.unquote(pair[0]).encode("UTF-8")]=urllib.parse.unquote(pair[1]).encode("UTF-8")
    logging.debug('===END POST====')
  except (ValueError):
    request_body_size = 0
  logging.debug('UNQUOTED post:{}'.format(post))
  return post
    
  '''
  if password matchs
    save private
    update public for all forms
  else
    if private=public and expiry>current time
      return true
    else
      return false
  '''
  
def verify_user(post):
  if(b'username' in post and b'password' in post):
    logging.debug('username and password are provided')
    #post is dictionary with  strings, not bytes (because split is there for str)
    m=myassql.my_sql()
    m.get_link(astm_var.my_host,astm_var.my_user,astm_var.my_pass,astm_var.my_db)
    cur=m.run_query('select * from user where user=%s',(post[b'username'].decode("UTF-8"),))
    user_info=m.get_single_row(cur)
    m.close_cursor(cur)
    m.close_link()
    
    logging.debug('user data:{}'.format(user_info))
    logging.debug('post data:{}'.format(post))

    '''
    Python: bcrypt.hashpw(b'mypassword',bcrypt.gensalt(rounds= 4,prefix = b'2b')
    PHP:    password_hash('mypassword',PASSWORD_BCRYPT);

    Python:bcrypt.checkpw(b'text',b'bcrypted password')
    PHP: password_verify('text,'bcrypted password')
    '''
    #try is required to cache NoneType exception when supplied hash is not bcrypt
    try:
      if(bcrypt.checkpw(post[b'password'],user_info[2].encode())):
        #pr,pb=get_private_public()
        public_key=insert_update_private_key(post[b'username'])
        return public_key
      else:
        return False
    except Exception as ex:
      logging.debug('{}'.format(ex))
      return False
  elif(b'public_key' in post):
    return verify_public_key(post[b'username'],post[b'public_key'])
  else:
    return False
  
def verify_public_key(username,public_key):
  private_key=retrive_private_key(username)
  logging.debug('public={}:  private={}'.format(public_key,private_key))
  if bcrypt.checkpw(private_key,public_key)==True:
    return public_key
  else:
    return False

def get_private_public():
  size=50
  chars=string.ascii_uppercase + string.digits
  private=''.join(random.choice(chars) for _ in range(size)).encode()
  public=bcrypt.hashpw(private,bcrypt.gensalt(rounds= 4,prefix = b'2b'))
  logging.debug('Private:{} Public:{}'.format(private,public))
  return (private, public)
  
def insert_update_private_key(username):
  pair=get_private_public()
  dt=datetime.datetime.now()+ datetime.timedelta(minutes=config.key_expiry_period)
  dt_str=dt.strftime("%Y-%m-%dT%H:%M:%S")
  m=myassql.my_sql()
  m.get_link(astm_var.my_host,astm_var.my_user,astm_var.my_pass,astm_var.my_db)
  cur=m.run_query('insert into logged (user,private,expire) values(%s,%s,%s) on duplicate key update private=%s , expire=%s',
                    (username.decode("UTF-8"),pair[0].decode("UTF-8"),dt_str,pair[0].decode("UTF-8"),dt_str))
  m.close_cursor(cur)
  m.close_link()
  return pair[1]

def retrive_private_key(username):
  current_date_time=datetime.datetime.now()
  dt_str=current_date_time.strftime("%Y-%m-%dT%H:%M:%S")
  m=myassql.my_sql()
  m.get_link(astm_var.my_host,astm_var.my_user,astm_var.my_pass,astm_var.my_db)
  cur=m.run_query('select * from logged where user=%s',username.decode("UTF-8"))
  logged_info=m.get_single_row(cur)
  m.close_cursor(cur)
  m.close_link()
  logging.debug('logged info:{}'.format(logged_info))  
  return logged_info[1].encode("UTF-8")
