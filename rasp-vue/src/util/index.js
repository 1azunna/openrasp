import axios from 'axios'
import Cookie from 'js-cookie'
import router from '@/router'

export var rasp_version = '1.3.5'

// 起始 type_id: 1001
export var audit_types = {
  1002:'Agent registration',
  1003:'Agent delete',
  1004:'Reset AppSecret',
  1005:'Deliver general configuration',
  1006:'Distribute whitelist configuration',
  1007:'Send algorithm configuration',
  1008:'Send alarm configuration',
  1009:'Send detection plug-in',
  1010:'Upload plugin',
  1011:'Remove plugin',
  1012:'Create application',
  1013:'Delete application',
  1014:'Update application information',
  1015:'Reset plugin configuration'
}

export var browser_headers = [{
  name:'X-Frame-Options',
  descr:'click hijacking protection',
  options: [{
    name:'Do not open',
    value: undefined
  },
  {
    name:'Reject (deny)',
    value:'deny'
  },
  {
    name:'Only allow same origin (sameorigin)',
    value:'sameorigin'
  }
  ]
},
{
  name:'X-Content-Type-Options',
  descr:'MIME sniffing protection',
  options: [{
    name:'Do not open',
    value: undefined
  },
  {
    name:'Open',
    value:'nosniff'
  }
  ]
},
{
  name:'X-XSS-Protection',
  descr:'XSS Auditor protection',
  options: [{
    name:'Do not open',
    value: undefined
  },
  {
    name:'Intercept mode',
    value: '1; mode=block'
  }
  ]
},
// {
// name: "X-Referrer-Policy",
// descr: "Referrer protection",
// options: [
// "no-referrer",
// "no-referrer-when-downgrade",
// "same-origin",
// "origin",
// "strict-origin",
// "origin-when-cross-origin",
// "strict-origin-when-cross-origin",
// "unsafe-url"
//]
// },
{
  name:'X-Download-Options',
  descr:'File download protection',
  options: [{
    name:'Do not open',
    value: undefined
  },
  {
    name:'Close automatic operation (noopen)',
    value:'noopen'
  }
  ]
}
]

export var baseline_types = {
  3001:'Cookie httpOnly check',
  3002:'Process start account check',
  3003:'Background weak password check',
  3004:'Insecure default application check',
  3005:'Open Directory Check',
  3006:'Database connection account audit',
  3007:'JBoss background no authentication check',
  // 3008:'Log leaks sensitive information',
  3009:'Web root directory sensitive files leaked',

  4001:'allow_url_include configuration audit',
  4002:'expose_php configuration audit',
  4003:'display_errors configuration audit',
  4004:'yaml.decode_php configuration audit'
}

export var attack_types = {
  sql:'SQL injection',
  sql_exception:'SQL statement exception',
  eval:'EVAL code execution',
  loadLibrary:'Class library loading',
  command:'Command execution',
  xxe:'XXE external entity loading',
  directory:'Directory traversal',
  rename:'File rename',
  readFile:'Any file read',
  deleteFile:'Any file delete',
  include:'Any file includes',
  writeFile:'Any file write',
  ssrf:'SSRF request forgery',
  ssrfRedirect:'SSRF request forgery (after redirection)',
  ognl:'OGNL code execution',
  webdav:'Any file upload (PUT)',
  fileUpload:'Any file upload',
  deserialization:'Transformer deserialization',
  xss_echo:'Echo XSS cross-site scripting attack',
  xss_userinput:'BODY XSS cross-site scripting attack',
  webshell_callable:'WebShell-Deformed Backdoor',
  webshell_eval:'WebShell-Chinese Kitchen Knife',
  webshell_command:'WebShell-command execution',
  webshell_file_put_contents:'WebShell-Backdoor upload',
  webshell_ld_preload:'WebShell-LD_PRELOAD backdoor',
  response:'HTTP response sampling detection',
  request:'Request start',
  link:'File link'
}

export var status_types = {
  block:'Intercept request',
  log:'Record log'
  // ignore:'Ignore release'
}

// Remove spaces and new lines, separate them according to the specified delimiter, and finally delete null/undefined/empty strings
export function trimSplit(data, sep) {
  var tmp = data.replace(/\s/g,'').split(sep)
  return tmp.filter(a => a)
}

export function convertToInt(data) {
  var tmp = []
  data.forEach (function (row) {
    tmp.push(parseInt(row))
  })

  return tmp.filter(a => a)
}

export function getDefaultConfig() {
  return {
    general_config: {
      'inject.custom_headers': {}
    },
    whitelist_config: [],
    email_alarm_conf: {
      recv_addr: []
    },
    ding_alarm_conf: {
      recv_user: [],
      recv_party: []
    },
    http_alarm_conf: {
      recv_addr: []
    },
    kafka_alarm_conf: {
      
    },
    general_alarm_conf: {

    }
  }
}

export function validateRegex(value) {
  var error = false
  try {
    new RegExp(value)
  } catch (e) {
    error ='Regular expression error:' + e.toString()
  }

  return error
}

export function block_status2name(status) {
  return status_types[status] || status
}

export function attack_type2name(id) {
  if (id =='webshell') {
    return'WebShell website backdoor'
  }

  if (id =='xss') {
    return'XSS cross-site scripting attack'
  }

  return attack_types[id] || id
}

export const request = axios.create({
  baseURL:
    process.env.NODE_ENV ==='production'
      ?'/'
      :'http://10.14.117.55:8080/',
  timeout: 8000
})
request.interceptors.request.use(
  config => {
    if (process.env.NODE_ENV !=='production') {
      config.headers['X-OpenRASP-Token'] =
        '9256a3555fbd4f24f7a2ba915a32261ab4c720fc'
    }
    return config
  },
  error => {
    console.error(error)
    Promise.reject(error)
  }
)
request.interceptors.response.use(
  response => {
    const res = response.data
    if (res.status !== 0) {
      if (res.status === 401) {
        Cookie.set('RASP_AUTH_ID', null)
        if (router.currentRoute.name !=='login') {
          router.push({
            name:'login',
            query: {
              redirect: location.href
            }
          })
        }
      } else {
        alert(response.config.url + 'Interface error:' + res.status + '-' + res.description)
      }
      return Promise.reject(res)
    } else {
      return res.data
    }
  },
  error => {
    alert('HTTP request error: response code '+ error.response.status)
    console.error(error)
    return Promise.reject(error)
  }
)