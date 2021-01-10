const plugin_version = '2020-1127-1930'
const plugin_name    = 'official'
const plugin_desc    = 'Official plugin'

/*
 * Copyright 2017-2019 Baidu Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Most used link
//
// Description of Web Attack Detection Capability, Introduction to Zero Rule Detection Algorithm
// https://rasp.baidu.com/doc/usage/web.html
//
// CVE vulnerability coverage description
// https://rasp.baidu.com/doc/usage/cve.html

'use strict'
var plugin  = new RASP(plugin_name)

// Detection logic switch
//
// block -> block and print the alarm log
// log -> print log without interception
// ignore -> turn off this algorithm

// BEGIN ALGORITHM CONFIG //

var algorithmConfig = {
    // 快速设置
    meta: {
        // If all_log is enabled, it means that it is in observation mode, and all blocks will be changed to log
        all_log: true,

        // If is_dev is enabled, it means the offline environment, and more performance-consuming detection algorithms will be enabled
        is_dev: false,

        // If log_event is enabled, application behavior information will be printed to plugin.log
        log_event: false,

        // schema version
        schema_version: 1
    },

    // SQL injection algorithm #1-match user input
    // 1. User input length is at least 8
    // 2. The user input contains at least one SQL keyword-namely pre_filter, [default closed]
    // 3. The user input appears completely in the SQL statement, and will cause the SQL statement logic to change
    sql_userinput: {
        name:       'Algorithm 1-User input matching algorithm',
        action:     'block',
        min_length: 8,
        pre_filter: 'select|file|from|;',
        pre_enable: false,
        anti_detect_filter: 'add|all|alter|analyze|and|any|as|asc|avg|begin|between|by|case|create|count|delete|desc|do|dumpfile|else|elseif|end|exists|false|file|float|flush|follows|from|group|having|identified|if|in|insert|interval|into|join|last|like|limit|loop|not|null|on|or|order|procedure|regexp|return|rlike|select|then|true|union|update|values|xor',
        anti_detect_enable: true,
        lcs_search: false,

       // Whether to allow the database manager-the front end to submit SQL statements directly
        allow_full: true
    },
    
    // SQL Injection Algorithm #2-Statement Specification
    sql_policy: {
        name:'Algorithm 2-Intercept abnormal SQL statements',
        action:  'block',

        // Rough rules-In order to reduce the number of tokenizes, only enter when the SQL statement contains certain characteristics
        // In addition, we only need to process the addition, deletion, modification, and check statement. Although the show statement can also report error injection, algorithm 2 does not need to process
        pre_filter: ';|\\/\\*|(?:\\d{1,2}\\s*,\\s*){2}|(?:null\\s*,\\s*){2}|0x[\\da-f]{8}|\\W(information_schema|outfile|dumpfile|load_file|benchmark|pg_sleep|sleep|is_srvrolemember|updatexml|extractvalue|hex|char|chr|mid|ord|ascii|bin)\\W',

        feature: {
           // Whether to prohibit multi-statement execution, select ...; update ...;
            stacked_query: false,

            // Whether to prohibit hexadecimal strings, select 0x41424344
            no_hex: false,

            // Prohibit version number comments, select/*!500001,2,*/3
            version_comment: true,

            // Function blacklist, see below for specific list, select load_file(...)
            function_blacklist: true,

            // Frequency of sensitive functions, see below for specific list, select chr(123)||chr(123)||chr(123)=chr(123)||chr(123)||chr(123)
            function_count: false,

            // Intercept union select NULL, NULL or union select 1,2,3,4
            union_null: true,

            // Whether to intercept into outfile write file operation
            into_outfile: true,

            // Whether to intercept information_schema related read operations, disabled by default
            information_schema: false
        },
        function_blacklist: {
            // File operation
            load_file:        true,

            // Time difference injection
            benchmark: true,
            sleep: true,
            pg_sleep: true,

            // detection phase
            is_srvrolemember: true,

            // error injection
            updatexml: true,
            extractvalue: true,

            // Blind injection function, some functions can be deleted if there are false positives
            hex:              false,
            mid:              false,
            ord:              false,
            ascii:            false,
            bin:              false
        },
        function_count: {
            chr:              5,
            char:             5
        }
    },

    sql_exception: {
        name:      'Algorithm 3-Record database exception',
        action:    'log',
        reference: 'https://rasp.baidu.com/doc/dev/official.html#sql-exception',

        // error_code is allowed at most 100, if it exceeds, clear it directly
        mysql: {
	        error_code: [
	            // 1045, // Access denied for user 'bae'@'10.10.1.1'
                // 1690, // DOUBLE value is out of range in 'exp(~((select 'root@localhost' from dual)))'
	            1060, // Duplicate column name '5.5.60-0ubuntu0.14.04.1'
	            1062, // Duplicate entry '::root@localhost::1' for key 'group_key'
	            1064, // You have an error in your SQL syntax
	            1105, // XPATH syntax error: '~root@localhost~'
	            1367  // Illegal non geometric 'user()' value found during parsing
	        ]
        },
        pgsql: {
            error_code: [
                "42601", // normal syntax error
                "22P02", // ERROR:  invalid input syntax for type double precision: "DATABASE: test1"
            ],
            error_state: [
                "42601", // normal syntax error
                "22P02", // ERROR:  invalid input syntax for type double precision: "DATABASE: test1"
            ]
        },
        sqlite: {
            error_code: [
                1, // generic error, like syntax error、malformed MATCH expression: ["3.6.23.1] and other
            ]
        },
        oracle: {
            error_code: [
                "ORA-29257", // host string unknown
                "ORA-20000", // Oracle Text error
                "ORA-00904", // invalid identifier
                "ORA-19202", // Error occurred in XML processing
                "ORA-01756", // quoted string not properly terminated
                "ORA-01740", // missing double quote in identifier
                "ORA-00920", // invalid relational operator
                "ORA-00907", // missing right parenthesis
                "ORA-00911", // invalid character
            ]
        },
        hsql: {
            error_code: [
                -5583, // malformed quoted identifier
                -5584, // malformed string
                -5590, // unexpected end of statement
            ],
            error_state: [
                "42583", // malformed quoted identifier
                "42584", // malformed string
                "42590", // unexpected end of statement
            ]
        },
        mssql: {
            error_code: [
                105, // Unclosed quotation mark after the character string '%.*ls'.
                245, // Conversion failed when converting the %ls value '%.*ls' to data type %ls.
            ]
        },
        db2: {
            error_state: [
                "42603", // The string constant beginning with "'xxx" does not have an ending string
            ]
        }
    },

    sql_regex: {
        name:      'Algorithm 4-Regular Expression Algorithm',
        action:    'ignore',
        regex:     'union.*select.*from.*information_schema'
    },

    // SSRF-from the user input, and the internal network address is intercepted
    ssrf_userinput: {
      name:'Algorithm 1-User input matching algorithm (support rebind detection)',
        action: 'block'
    },
    // SSRF-whether to allow access to aws metadata
    ssrf_aws: {
        name:  'Algorithm 2-Intercept AWS/Aliyun/GCP metadata access',
        action: 'block'
    },
    // SSRF-whether to allow access to dnslog address
    ssrf_common: {
        name:'Algorithm 3-Block common dnslog addresses',
        action:  'block',
        domains: [
        	'.vuleye.pw',
            '.ceye.io',
            '.exeye.io',
            '.vcap.me',
            '.xip.name',
            '.xip.io',
            '.sslip.io',
            '.nip.io',
            '.burpcollaborator.net',
            '.tu4.org',
            '.2xss.cc',
            '.bxss.me',
            '.godns.vip'
        ]
    },
   // SSRF-whether to allow access to the obfuscated IP address
    ssrf_obfuscate: {
        name:'Algorithm 4-Intercept obfuscated addresses',
        action: 'block'
    },
    // SSRF-It is forbidden to use curl to read content like file:///etc/passwd, php://filter/XXXX
    ssrf_protocol: {
        name:'Algorithm 5-Intercept abnormal protocols such as php://',
        action:    'block',
        protocols: [
            'file',
            'gopher',

            // python specific
            'local_file',
            'local-file',

            // java specific
            'jar',
            'netdoc',

            // php specific
            'dict',
            'php',
            'phar',
            'compress.zlib',
            'compress.bzip2'
        ]
    },

   // Arbitrary file download protection-from user input
    readFile_userinput: {
        name:'Algorithm 1-User input matching algorithm',
        action:     'block',
        lcs_search: false
    },
   // Arbitrary file download protection-Use file_get_contents and other functions to read http(s):// content (note that it is not distinguished whether it is an intranet address)
    readFile_userinput_http: {
        name:'Algorithm 2-User input matching algorithm + http protocol',
        action: 'block'
    },
    // Arbitrary file download protection-use file_get_contents and other functions to read file://, php:// protocols
    readFile_userinput_unwanted: {
        name:'Algorithm 3-Intercept abnormal protocols such as php://',
        action: 'block'
    },
   // Arbitrary file download protection-use ../../ to jump out of the web directory to read sensitive files
    readFile_outsideWebroot: {
        name:'Algorithm 4-It is forbidden to use ../../ to access files outside the web directory',
        action:    'ignore',
        reference: 'https://rasp.baidu.com/doc/dev/official.html#case-out-webroot'
    },
   // Arbitrary file download protection-read sensitive files, the last line of defense
    readFile_unwanted: {
        name:'Algorithm 5-File Probe Algorithm',
        action: 'log'
    },

    // Write file operation-NTFS stream
    writeFile_NTFS: {
      name:'Algorithm 1-Intercept NTFS::$DATA write operation',
        action: 'block'
    },
  // File writing operation-PUT upload script file-Cannot associate the actually uploaded file with the file writing operation, comment out temporarily
    // writeFile_PUT_script: {
    // name:'Algorithm 2-Intercept PUT to upload script files such as php/jsp',
    // action:'block'
    // },
    // Write file operation-script file
    // https://rasp.baidu.com/doc/dev/official.html#case-file-write
    writeFile_script: {
        name:'Algorithm 2-Intercept the writing of script files such as php/jsp',
        reference:'https://rasp.baidu.com/doc/dev/official.html#case-file-write',
        action:'block',
        userinput: true,
        lcs_search: false
    },

    writeFile_reflect: {
        name:'Algorithm 3-Intercept file writing operations performed through reflection and deserialization',
        action:    'log'
    },

    // Delete any file-use ../ to jump out of the directory
    deleteFile_userinput: {
        name:'Algorithm 1-User input matches, use of ../delete files is prohibited',
        action:'block',
        lcs_search: false
    },

    // Rename monitoring-rename ordinary files to webshell,
    // Cases include the MOVE method to upload the backdoor, CVE-2018-9134 dedecms v5.7 background rename getshell
    rename_webshell: {
        name:'Algorithm 1-Get WebShell by renaming',
        action: 'block'
    },
    // copy_webshell: {
    //     action: 'block'
    // },

    link_webshell: {
        name:'Algorithm 1-Get WebShell through link',
        action:'block'
    },

    // File Manager-User input matches, only detect when the absolute path is directly read
    directory_userinput: {
        name:'Algorithm 1-User input matching algorithm',
        action:'block',
        lcs_search: false
    },
    // File Manager-Reflect to list directories
    directory_reflect: {
        name:'Algorithm 2-Call through reflection to view the contents of the directory',
        action:'block'
    },
    // File manager-view sensitive directories
    directory_unwanted: {
        name:'Algorithm 3-Try to view sensitive directories',
        action:'log'
    },

    // File contains-user input matches
    include_userinput: {
        name:'Algorithm 1-User input matching algorithm',
        action:     'block',
        lcs_search: false
    },
    // File contains-special agreement
    include_protocol: {
        name:'Algorithm 2-Try to include exception protocols such as jar://',
        action: 'block',
        protocols: [
            'file',
            'gopher',

            // java specific
            'jar',
            'netdoc',

            // php stream
            'http',
            'https',

            // php specific
            'dict',
            'php',
            // 'phar',
            'compress.zlib',
            'compress.bzip2',
            'zip',
            'rar'
        ]
    },

    // XXE-code security switch, directly prohibit external entities by calling related functions
    xxe_disable_entity: {
        name:'Algorithm 1-prohibit external entity loading (logging is equivalent to completely ignoring)',
        action: 'ignore',
        clazz:  {
            // com/sun/org/apache/xerces/internal/jaxp/DocumentBuilderFactoryImpl
            java_dom:   true,

            // org/dom4j/io/SAXReader
            java_dom4j: true,

            // org/jdom/input/SAXBuilder,org/jdom2/input/SAXBuilder
            java_jdom:  true,

            // com/sun/org/apache/xerces/internal/jaxp/SAXParserFactoryImpl
            java_sax:   true,

            // javax/xml/stream/XMLInputFactory
            java_stax:  true
        }
    },

    // XXE-Use gopher/ftp/dict/.. and other unusual protocols to access external entities
    xxe_protocol: {
        name:'Algorithm 2-Use ftp:// and other abnormal protocols to load external entities',
        action: 'block',
        protocols: [
            'ftp',
            'dict',
            'gopher',
            'jar',
            'netdoc'
        ]
    },
    // XXE-Use the file protocol to read the content, may be falsely reported, the default log
    xxe_file: {
        name:'Algorithm 3-Use file:// protocol to read files',
        reference: 'https://rasp.baidu.com/doc/dev/official.html#case-xxe',
        action:    'log',
    },

   // File upload-COPY/MOVE method, only suitable for tomcat
    fileUpload_webdav: {
        name:'Algorithm 1-Upload script file by MOVE',
        action:'block'
    },
    // File upload-upload script file in Multipart mode
    fileUpload_multipart_script: {
        name:'Algorithm 2-Upload script files such as PHP/JSP in Multipart mode',
        action:'block'
    },
    // File upload-upload HTML/JS and other files in Multipart
    fileUpload_multipart_html: {
        name:'Algorithm 3-Multipart upload HTML/JS and other files',
        action:'ignore'
    },
    // File upload-upload DLL/EXE and other files in Multipart
    fileUpload_multipart_exe: {
        name:'Algorithm 3-Upload DLL/EXE and other files in Multipart mode',
        action:'ignore'
    },

    // OGNL code execution vulnerability
    ognl_exec: {
        name:'Algorithm 1-Execute abnormal OGNL statement',
        action:'block'
    },

    // Command execution-java reflection, deserialization, php eval, etc.
    command_reflect: {
        name:'Algorithm 1-execute commands through reflection, such as deserialization and encryption backdoor',
        action: 'block'
    },
    // Command injection-command execution backdoor, or command injection
    command_userinput: {
        name:'Algorithm 2-User input matching algorithm, including command injection detection',
        action:'block',
        min_length: 2,
        java_unexploitable_filter: true,
    },
    // Command injection-common commands
    command_common: {
        name:'Algorithm 3-Identify common penetration commands (probes)',
        action:  'log',
        pattern: 'cat.{1,5}/etc/passwd|nc.{1,30}-e.{1,100}/bin/(?:ba)?sh|bash\\s-.{0,4}i.{1,20}/dev/tcp/|subprocess.call\\(.{0,6}/bin/(?:ba)?sh|fsockopen\\(.{1,50}/bin/(?:ba)?sh|perl.{1,80}socket.{1,120}open.{1,80}exec\\(.{1,5}/bin/(?:ba)?sh'
    },
    // Command execution-syntax errors and sensitive operations
    command_error: {
        name:'Algorithm 4-Find syntax errors and sensitive operations',
        action:'log',

        unbalanced_quote_enable: true,

        sensitive_cmd_enable: true,
        concat_char: ["|", ";"],
        sensitive_cmd: ["curl", "bash", "cat", "sh"],

        alarm_token_enable: true,
        alarm_token: ["$IFS", "${IFS}"]
    },
    // Command execution-whether to block all command execution? If there is no need to execute the command, it can be changed to block to ensure the security of the server to the greatest extent
    command_other: {
        name:'Algorithm 5-Record or intercept all command execution operations',
        action: 'ignore'
    },

    // transformer deserialization attack
    deserialization_transformer: {
        name:'Algorithm 1-intercept transformer deserialization attack',
        action:'block'
    },

    // xss user input matching algorithm
    // 1. When the length of the user input exceeds 15, it matches the label regular and appears in the response, directly intercept
    // 2. When the length of the user input exceeds 15, and the number of parameters matching the label regular exceeds 10, it is judged as a scanning attack and directly intercepted (abandoned after v1.1.2)
    xss_userinput: {
        name:'Algorithm 2-Intercept the reflected XSS output in the response',
        action: 'ignore',

        filter_regex: "<![\\-\\[A-Za-z]|<([A-Za-z]{1,12})[\\/>\\x00-\\x20]",
        min_length:   15,

        // v1.1.2 之后废弃
        max_detection_num: 10
    },

    // php proprietary algorithm
    xss_echo: {
        name:'Algorithm 1-PHP: Direct output of GPC parameters is prohibited',
        action: 'log',

        filter_regex: "<![\\-\\[A-Za-z]|<([A-Za-z]{1,12})[\\/>\\x00-\\x20]"
    },    

   webshell_eval: {
        name:'Algorithm 1-Intercept a simple PHP Chinese kitchen knife backdoor',
        action:'block'
    },

    webshell_command: {
        name:'Algorithm 2-Intercept simple PHP command execution backdoor',
        action:'block'
    },

    webshell_file_put_contents: {
        name:'Algorithm 3-intercept simple PHP file upload backdoor',
        action:'block'
    },

    webshell_callable: {
        name:'Algorithm 4-Intercept simple PHP array_map/walk/filter backdoor',
        action: 'block',
        functions: [
            'system', 'exec', 'passthru', 'proc_open', 'shell_exec', 'popen', 'pcntl_exec', 'assert'
        ]
    },

   webshell_ld_preload: {
        name:'Algorithm 5-Intercept PHP LD_PRELOAD mechanism backdoor',
        action: 'block'
    },

    eval_regex: {
        name:   'Algorithm 1-Regular Expression',
        action: 'ignore',
        regex:  'base64_decode|gzuncompress|create_function'
    },

    loadLibrary_unc: {
        name:   'Algorithm 1-Intercept UNC path class library loading',
        action: 'block'
    },

   // loadLibrary_other: {
    // name:'Algorithm 2-Record or intercept all class library loading',
    // action:'ignore'
    // },

    response_dataLeak: {
        name:'Algorithm 1-Check whether there is sensitive information in the response (interception is equal to logging)',
        action:'ignore',

       // check type
        kind: {
            phone:         true,
            identity_card: true,
            bank_card:     true
        },

        // Content-Type 过滤
        content_type: 'html|json|xml'
    }
}

// END ALGORITHM CONFIG //

// Configure mounting to global RASP variables
RASP.algorithmConfig = algorithmConfig

const clean = {
    action:     'ignore',
    message:    'Looks fine to me',
    confidence: 0
}

var forcefulBrowsing = {
    dotFiles: /\.(7z|tar|gz|bz2|xz|rar|zip|sql|db|sqlite)$/,
    nonUserDirectory: /^\/(proc|sys|root)/,

   // webdav file probe-the most frequently downloaded file
    unwantedFilenames: [
        // user files
        '.DS_Store',
        'id_rsa', 'id_rsa.pub', 'known_hosts', 'authorized_keys',
        '.bash_history', '.csh_history', '.zsh_history', '.mysql_history',

        // project files
        '.htaccess', '.user.ini',

        'web.config', 'web.xml', 'build.property.xml', 'bower.json',
        'Gemfile', 'Gemfile.lock',
        '.gitignore',
        'error_log', 'error.log', 'nohup.out',
    ],

    // Directory Probe-webshell to view the most frequently viewed directory
    unwantedDirectory: [
        '/',
        '/home',
        '/var/log',
        '/private/var/log',
        '/proc',
        '/sys',
        'C:\\',
        'D:\\',
        'E:\\'
    ],

    // File Probe-webshell view the most frequently viewed files
    absolutePaths: [
	    '/etc/issue',
        '/etc/shadow',
        '/etc/passwd',
        // '/etc/hosts',
        '/etc/apache2/apache2.conf',
        '/root/.bash_history',
        '/root/.bash_profile',
        'c:\\windows\\system32\\inetsrv\\metabase.xml',
        'c:\\windows\\system32\\drivers\\etc\\hosts'
    ]
}

// Specify the header name to be detected when detecting header injection, uniformly use lowercase
var headerInjection = ["user-agent", "referer", "x-forwarded-for"]

// If you configure unconventional extension mapping, such as making .abc execute as a PHP script, then you may need to add more extensions
var scriptFileRegex = /\.(aspx?|jspx?|php[345]?|phtml|sh|py|pl|rb)\.?$/i

// normal file
var cleanFileRegex = /\.(jpg|jpeg|png|gif|bmp|txt|rar|zip)$/i

// File read extension whitelist, including compressed files, office files, picture files
var readFileWhiteExt = new RegExp(/\.(do[c|t][x|m|]?|xl[s|t][x|m|b]?|pp[t|s|a][x| m]?|pot[x|m]|7z|tar|gz|bz2|xz|rar|zip|jpg|jpeg|png|gif|bmp|txt|)$/,'i')

// Match HTML/JS and other files that can be used for phishing and domain-fronting
var htmlFileRegex = /\.(htm|html|js)$/i

// Match executable files such as EXE/DLL
var exeFileRegex = /\.(exe|dll|scr|vbs|cmd|bat)$/i

// other streams are useless
var ntfsRegex = /::\$(DATA|INDEX)$/

// Known user input matching algorithm false positives: pass in 1,2,3,4 -> IN(1,2,3,4) and pass in column_name, column_pass -> select column_name, column_pass from xxx
var commaSeparatedRegex = /^(, *)?(([a-zA-Z_]\w*|[0-9+\-x\.]+) *, *)+([a-zA-Z_]\ w*|[0-9+\-x\.]+)$/

// match the intranet address
var internalRegex = /^(0\.0\.0|127|10|192\.168|172\.(1[6-9]|2[0-9]|3[01]))\./

// ssrf whitelist hostname
var whiteHostName = /\.bcebos\.com$|(^|\.)oss-[\d\w\-]{0,30}\.aliyuncs\.com$/

// SQL injection algorithm 1-pre-filtering regular
var sqliPrefilter1 = new RegExp(algorithmConfig.sql_userinput.pre_filter,'i')

// SQL injection algorithm 1-reverse detection regular
var sqliAntiDetect = new RegExp(algorithmConfig.sql_userinput.anti_detect_filter,'i')

// SQL injection algorithm 2-pre-filtering regular
var sqliPrefilter2 = new RegExp(algorithmConfig.sql_policy.pre_filter,'i')

// SQL injection algorithm-manager whitelist
var sqliWhiteManager = new RegExp(/phpmyadmin/,'i')

// java matching command injection may be available
var cmdJavaExploitable = new RegExp(/^[^ ]*sh.{1,12}-c/,'i')

// Command execution probe-common penetration commands
var cmdPostPattern = new RegExp(algorithmConfig.command_common.pattern,'i')

// Leakage of sensitive information-Content Type regular
var dataLeakContentType = new RegExp(algorithmConfig.response_dataLeak.content_type, 'i')

if (! RASP.is_unittest)
{
  // Logging mode: change all blocks to log
   if (algorithmConfig.meta.all_log)
   {
        Object.keys(algorithmConfig).forEach(function (name) {
            // XXE external entity switch is not affected
            if (name != 'xxe_disable_entity')
            {
                if (algorithmConfig[name].action == 'block') 
                {
                    algorithmConfig[name].action = 'log'
                }
            }
        })
    }

   // Research and development mode:
    // 1. Open more detection algorithms that consume performance
    // 2. In case of non-attack, the system will report to the police if a vulnerability is detected
    if (algorithmConfig.meta.is_dev)
    {
        // Turn off select pre-filtering regular
        algorithmConfig.sql_userinput.pre_enable = false

        // Turn off 1,2,3 false positive filtering
        commaSeparatedRegex = /^$/

        // Turn off xss_echo non-attack filtering
        algorithmConfig.xss_echo.filter_regex = ""
    }
}
else {
    algorithmConfig.eval_regex.action = "log"
}

// Verify that sql_regex is legal
if (algorithmConfig.sql_regex.action != 'ignore') {
    if (! algorithmConfig.sql_regex.regex.trim()) {
        plugin.log ("algorithmConfig.sql_regex.regex is empty, algorithm disabled")
        algorithmConfig.sql_regex.action = 'ignore'
    } else {
        try {
            new RegExp(algorithmConfig.sql_regex)
        } catch (e) {
            plugin.log ("Invalid regex in algorithmConfig.sql_regex.regex: ", e)
            algorithmConfig.sql_regex.action = 'ignore'
        } 
    }
}

// Verify whether eval_regex is legal
if (algorithmConfig.eval_regex.action != 'ignore') {
    if (! algorithmConfig.eval_regex.regex.trim()) {
        plugin.log ("algorithmConfig.eval_regex.regex is empty, algorithm disabled")
        algorithmConfig.eval_regex.action = 'ignore'
    } else {
        try {
            new RegExp(algorithmConfig.eval_regex)
        } catch (e) {
            plugin.log ("Invalid regex in algorithmConfig.eval_regex.regex: ", e)
            algorithmConfig.eval_regex.action = 'ignore'
        } 
    }
}


// Commonly used functions
String.prototype.replaceAll = function(token, tokenValue, maxLength) {
    if (maxLength === undefined) {
        maxLength = 4096
    }
    //Null value judgment to prevent infinite loop
    if (! token || token.length == 0 || this.length > maxLength) {
        return this
    }

    var index  = 0;
    var string = this;

    do {
        string = string.replace(token, tokenValue);
    } while((index = string.indexOf(token, index)) > -1);

    return string
}

// function canonicalPath (path) {
//     return path.replaceAll('/./', '/').replaceAll('//', '/').replaceAll('//', '/')
// }

//We no longer need to simplify the path. When two /../ or two \..\ appear, it can be judged as a path traversal attack, e.g
// /./././././home/../../../../etc/passwd
// \\..\\..\\..
// \/..\/..\/..
function has_traversal (path) {

    // Left and right slashes are treated equally
    var path2 = "/" + path.replaceAll('\\','/') + "/"
    // Overwrite ../../
    // as well as /../../
    var left  = path2.indexOf('/../')
    var right = path2.lastIndexOf('/../')

    if (left != -1 && right != -1 && left != right)
    {
        return true
    }

    return false
}

//Determine whether the parameter includes path traversal, which is more strict than path
function param_has_traversal (param) {
    // Left and right slashes are treated equally
    var path = "/" + param.replaceAll('\\', '/') + "/"

    if (path.indexOf("/../") != -1)
    {
        return true
    }
    return false
}

function is_hostname_dnslog(hostname) {
    var domains = algorithmConfig.ssrf_common.domains

    if (hostname == 'requestb.in' || hostname == 'transfer.sh')
    {
        return true
    }

    for (var i = 0; i < domains.length; i ++)
    {
        if (hostname.endsWith(domains[i]))
        {
            return true
        }
    }

    return false
}


// function basename (path) {
//     // Simple processing, support windows/linux at the same time
//     var path2 = path.replaceAll('\\', '/')
//     var idx   = path2.lastIndexOf('/')
//     return path.substr(idx + 1)
// }

// function has_file_extension(path) {
//     var filename = basename(path)
//     var index    = filename.indexOf('.')

//     if (index > 0 && index != filename.length - 1) {
//         return true
//     }

//     return false
// }

function validate_stack_java(stacks) {
    var known    = {
        'com.thoughtworks.xstream.XStream.unmarshal':                                   "Using xstream library",
        'java.beans.XMLDecoder.readObject':                                             "Using WebLogic XMLDecoder library",
        'org.apache.commons.collections4.functors.InvokerTransformer.transform':        "Using Transformer library (v4)",
        'org.apache.commons.collections.functors.InvokerTransformer.transform':         "Using Transformer library",
        'org.apache.commons.collections.functors.ChainedTransformer.transform':         "Using Transformer library",
        'org.jolokia.jsr160.Jsr160RequestDispatcher.dispatchRequest':                   "Using JNDI library (JSR 160)",
        'com.sun.jndi.rmi.registry.RegistryContext.lookup':                             "Using JNDI registry service",
        'org.apache.xbean.propertyeditor.JndiConverter':                                "Using JNDI binding class",
        'com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig':                "Using JTA transaction manager",
        'com.sun.jndi.url.ldap.ldapURLContext.lookup':                                  "Using LDAP factory service",
        'com.alibaba.fastjson.JSON.parseObject':                                        "Using fastjson library",
        'org.springframework.expression.spel.support.ReflectiveMethodExecutor.execute': "Using SpEL expressions",
        'freemarker.template.utility.Execute.exec':                                     "Using FreeMarker template",
        'org.jboss.el.util.ReflectionUtil.invokeMethod':                                "Using JBoss EL method",
        'org.codehaus.groovy.runtime.ProcessGroovyMethods.execute':                     "Using Groovy library",
        'bsh.Reflect.invokeMethod':                                                     "Using BeanShell library",
        'jdk.scripting.nashorn/jdk.nashorn.internal.runtime.ScriptFunction.invoke':     "Using Nashorn engine",
        'org.apache.shiro.io.DefaultSerializer.deserialize':                            "Using Shiro framework (DefaultSerializer)"    
    }

    var userCode = false, reachedInvoke = false, i = 0, message = undefined

    //v1.1.1 requires the com.baidu.openrasp related classes to be filtered in the stack, because it is not implemented correctly, an extra reflection stack is generated, and compatibility is required to prevent false positives.
    // v1.1.2 fixes this problem, that is, the top of the stack is the command execution method
    if (stacks.length > 3
        && stacks[0].startsWith('sun.reflect.GeneratedMethodAccessor')
        && stacks[1] == 'sun.reflect.GeneratedMethodAccessorImpl.invoke'
        && stacks[2] == 'java.lang.reflect.Method.invoke')
    {
        i = 3
    }

    for (; i < stacks.length; i ++) {
        var method = stacks[i]                

       // Check whether the user code is included between the reflection call -> command execution
        if (! reachedInvoke) {
            if (method == 'java.lang.reflect.Method.invoke') {
                reachedInvoke = true
            }

            // User code, that is, non-JDK, com.baidu.openrasp related functions
            if (! method.startsWith('java.') 
                && !method.startsWith('sun.') 
                && !method.startsWith('com.sun.') 
                && !method.startsWith('com.baidu.openrasp.')) 
            {
                userCode = true
            }
        }

        if (method.startsWith('ysoserial.Pwner')) {
            message = "Using YsoSerial tool"
            break
        }

        if (method.startsWith('net.rebeyond.behinder')) {
            message = "Using BeHinder defineClass webshell"
            break
        }

        if (method.startsWith('com.fasterxml.jackson.databind.')) {
            message = "Using Jackson deserialze method"
            break
        }

        // For the following types of reflection calls:
        // 1. Intercept only when the command comes directly from the reflection call
        // 2. If a class is generated by reflection, this class actively executes the command, it is ignored
        if (! userCode) {
            if (method == 'ognl.OgnlRuntime.invokeMethod') {
                message = "Using OGNL library"
                break
            }  else if (method == 'java.lang.reflect.Method.invoke') {
                message = "Unknown vulnerability detected"
            }
        }

        if (known[method]) {
            message = known[method]
        }
    }
    return message
}

function validate_stack_php(stacks) {
    var verdict = false
    var eval_count = 0

    for (var i = 0; i < stacks.length; i ++) {
        var stack = stacks[i]

        // from eval/assert/create_function/...
        if (stack.indexOf('runtime-created function') != -1
            || stack.indexOf('regexp code@') != -1) {
            verdict = true
            break
        }
       // eval/assert appears more than twice before it is considered a webshell
        if (stack.indexOf('eval()\'d code') != -1
            || stack.indexOf('assert code@') != -1) {
            eval_count++
            if (eval_count > 1) {
                verdict = true
                break
            }
        }

         // call_user_func/call_user_func_array two functions are called frequently
        // It must be intercepted by call_user_func directly calling system/exec and other functions, otherwise there will be many false positives
        if (stack.indexOf('@call_user_func') != -1) {
            // Filter the internal security coding library
            if (stack. indexOf('safesdk-php') != -1) {
                continue
            }
            if (i <= 1) {
                verdict = true
                break
            }
        }
    }

    return verdict
}

function is_absolute_path(path, is_windows) {

    // Windows - C:\\windows
    if (is_windows) {

        if (path[1] == ':')
        {
            var drive = path[0].toLowerCase()
            if (drive >= 'a' && drive <= 'z')
            {
                return true
            }
        }
    }

    // Unices - /root/
    return path[0] === '/'
}

function is_outside_webroot(appBasePath, realpath, path) {
    var verdict = false

    // If the specified path is null, the directory traversal is not verified
    if (path == null || has_traversal(path)) {
        // AppBasePath may not be obtained after servlet 3.X, or it may be empty
        // Add a judgment in advance to prevent false positives due to bugs
        if (! appBasePath || appBasePath.length == 0) {
            verdict = false
        }
        else if (realpath.indexOf(appBasePath) == -1) {
            verdict = true
        }
    }

    return verdict
}

// Does the path come from user input
// file_get_contents("/etc/passwd");
// file_get_contents("../../../../../../../etc/passwd");
//
// or end with user input
// file_get_contents("/data/uploads/" . "../../../../../../../etc/passwd");
function is_path_endswith_userinput(parameter, target, realpath, is_windows, is_lcs_search)
{
    var verdict = false

    Object.keys(parameter).some(function (key) {
       // Only handle non-array and hash situations
        Object.values(parameter[key]).some(function (value){
            // Only handle string type
            if (typeof value !='string') {
                return
            }
            // If the application does special processing, such as passing in file:///etc/passwd, what you actually see is /etc/passwd
            if (value.startsWith('file://') && 
                is_absolute_path(target, is_windows) && 
                value.endsWith(target)) 
            {
                verdict = true
                return true
            }

            // Remove redundant / and \ paths
            var simplifiedValue
            var simplifiedTarget

            // under Windows
            // Pass in ../../../conf/tomcat-users.xml
            // see c:\tomcat\webapps\root\..\..\conf\tomcat-users.xml
            if (is_windows) {
                value = value.replaceAll('/', '\\')
                target = target.replaceAll('/', '\\')
                realpath = realpath.replaceAll('/', '\\')
                simplifiedTarget = target.replaceAll('\\\\','\\').replaceAll('\\.\\', '\\')
                simplifiedValue = value.replaceAll('\\\\','\\').replaceAll('\\.\\', '\\')
            } else{
                simplifiedTarget = target.replaceAll('//','/').replaceAll('/./', '/')
                simplifiedValue = value.replaceAll('//','/').replaceAll('/./', '/')
            }
            var simplifiedValues
            if ( is_lcs_search ) {
                simplifiedValues = lcs_search( simplifiedValue, simplifiedTarget )
            }
            else {
                simplifiedValues = [simplifiedValue]
            }
            for(var i = 0, len = simplifiedValues.length; i < len; i++) {
                simplifiedValue = simplifiedValues[i]
                // The parameter must have a jump out of the directory, or an absolute path
                if ((target.endsWith(value) || simplifiedTarget.endsWith(simplifiedValue))
                    && (param_has_traversal(value) || value == realpath || simplifiedValue == realpath))
                {
                    verdict = true
                    return true
                }
            }
        })
        if (verdict){
            return true
        }
    })
    return verdict
}

// Check if user input is included-suitable for directory
function is_path_containing_userinput(parameter, target, is_windows, is_lcs_search)
{
    var verdict = false
    if (is_windows) {
        target = target.replaceAll('/', '\\').replaceAll('\\\\', '\\')
    }
    else{
        target = target.replaceAll('//', '/')
    }

    Object.keys(parameter).some(function (key) {
        var values = parameter[key]
        Object.values(values).some(function(value){
            // Only handle string type
            if (typeof value != 'string') {
                return
            }
            if (is_windows) {
                value = value.replaceAll('/', '\\').replaceAll('\\\\', '\\')
            }
            else {
                value = value.replaceAll('//', '/')
            }
            var values
            if (is_lcs_search) {
                values = lcs_search(value, target)
            }
            else {
               // Below java, passing in /usr/ will become /usr, so one less character is matched
                if ( value.charAt(value.length - 1) == "/" || 
                    value.charAt(value.length - 1) == "\\" ) {
                    value = value.substr(0, value.length - 1)
                }
                values = [value]
            }
            for(var i = 0, len = values.length; i < len; i++) {
                // Only handle non-array and hash situations
                if (param_has_traversal(values[i]) && target.indexOf(values[i]) != -1) {
                    verdict = true
                    return true
                }
            }
        })
        if (verdict){
            return true
        }
    })
    return verdict
}

// Whether from user input-suitable for any type of parameter
function is_from_userinput(parameter, target)
{
    var verdict = false
    Object.keys(parameter).some(function (key) {
        var values = parameter[key]
        Object.values(values).some(function(value){
            // Only handle non-array and hash situations
            if (value == target) {
                verdict = true
                return true
            }
        })
    })
    return verdict
}

// Whether from user input-suitable for any type of parameter
function is_from_userinput(parameter, target)
{
    var verdict = false
    Object.keys(parameter).some(function (key) {
        var values = parameter[key]
        Object.values(values).some(function(value){
           // Only handle non-array and hash situations
            if (value == target) {
                verdict = true
                return true
            }
        })
    })
    return verdict
}

//Included in user input - suitable for any type of parameter
function is_include_in_userinput(parameter, target)
{
    var verdict = false
    Object.keys(parameter).some(function (key) {
        var values = parameter[key]
        Object.values(values).some(function(value){
            // Only non-array, hash cases are processed
            if (value.indexOf(target) != -1) {
                verdict = true
                return true
            }
        })
    })
    return verdict
}

// Check whether the logic is modified by user parameters
function is_token_changed(raw_tokens, userinput_idx, userinput_length, distance, is_sql)
{
    if (is_sql === undefined) {
        is_sql = false
    }
    // When the user input traverses multiple tokens, it can be judged as code injection, the default is 2
    var start = -1, end = raw_tokens.length, distance = distance || 2

    // Find the starting point of token, you can change to binary search
    for (var i = 0; i < raw_tokens.length; i++)
    {
        if (raw_tokens[i].stop > userinput_idx)
        {
            start = i
            break
        }
    }
    // Comments may end up preventing cross-bordering caused by removing comments
    if (start == -1) {
        return false
    }

    // Find the end point of the token
    // Need to return the real distance, delete at most distance token i <start + distance condition
    for (var i = start; i < raw_tokens.length; i++)
    {
        if (raw_tokens[i].stop >= userinput_idx + userinput_length)
        {
            end = i
            break
        }
    }

    var diff = end - start + 1
    if (diff >= distance) {
        if (is_sql && algorithmConfig.sql_userinput.anti_detect_enable && diff < 10) {
            var non_kw = 0
            for (var i = start; i <= end; i++) {
                sqliAntiDetect.test(raw_tokens[i].text) || non_kw ++
                if (non_kw >= 2) {
                    return true
                }
            }
            return false
        }
        return true
    }
    return false
}

// Find the longest common substring of str1 and str2, and return an array of all the longest substrings
function lcs_search(str1, str2){
    var len1 = str1.length;
    var len2 = str2.length;
    var dp_arr = [[],[]]
    var pre = 1
    var now = 0
    var result =0
    var result_pos = []

    for (var i = 0; i <= len2+1; i ++) {
        dp_arr[0][i] = 0
        dp_arr[1][i] = 0
    }
    for (var i = 0; i <= len1; i ++) {
        for (var j = 0; j <= len2; j ++) {
            if ( i == 0 || j == 0 ){
                dp_arr[now][j] = 0
            }
            else if ( str1[i-1] == str2[j-1] ) {
                dp_arr[now][j] = dp_arr[pre][j-1] + 1
                if (dp_arr[now][j] > result){
                    result = dp_arr[now][j]
                    result_pos = [i - result]
                }else if (dp_arr[now][j] == result){
                    result_pos.push( i - result )
                }
            }
            else {
                dp_arr[now][j] = 0
            }
        }
        if( now == 0 ){
            now = 1
            pre = 0
        }
        else {
            now = 0
            pre = 1
        }
    }
    var result_pos_set = new Set(result_pos)
    var result_str = new Set()
    for (var item of result_pos_set) {
        result_str.add(str1.substr(item, result))
    }
    return Array.from(result_str)
}

// Parse cookie from string
function get_cookies(cookie_str) {
    cookie_items = cookie_str.split(';')
    var result = {}
    for(i = 0; i < cookie_items.length; i++) {
        item = cookie_items[i].trim()
        if (item.length == 0) {
            continue
        }
        else {
            key_len = item.indexOf("=")
            if (key_len <= 0) {
                continue
            }
            key = unescape(item.substr(0, key_len))
            value = unescape(item.substr(key_len + 1))
            result[key] = value
        }
    }
    return result
}

// Combine the header, cookie, parameter, and json parameters in context.parameter, and the key of header and cookie will be renamed
function get_all_parameter(context) {
    if (context.get_all_parameter !== undefined) {
        return context.parameter || {}
    }
    context.get_all_parameter = true
    var key_num = 0
    var parameter = context.parameter || {}
    if (context.header != null) {
        for (name in context.header) {
            if (name.toLowerCase() == "cookie") {
                var cookies = get_cookies(context.header.cookie)
                for (name in cookies) {
                    while ("cookie" + key_num + "_" + name in parameter) {
                        key_num++
                    }
                    parameter["cookie" + key_num + "_" + name] = [cookies[name]]
                }
            } else if (headerInjection.indexOf(name.toLowerCase()) != -1) {
                while ("header" + key_num + "_" + name in parameter) {
                    key_num++
                }
                parameter["header" + key_num + "_" + name] = [context.header[name]]
            }
        }
    }
    var jsons = [
        [context.json || {}, "input_json"]
    ]
    while (jsons.length > 0) {
        var json_arr = jsons.pop()
        var crt_json_key = json_arr[1]
        var json_obj = json_arr[0]
        for (item in json_obj) {
            if (typeof json_obj[item] == "string") {
                while ("json" + key_num + "_" + crt_json_key + "->" + item in parameter) {
                    key_num++
                }
                parameter["json" + key_num + "_" + crt_json_key + "->" + item] = [json_obj[item]]
            } else if (typeof json_obj[item] == "object") {
                jsons.push([json_obj[item], crt_json_key + "->" + item])
            }
        }
    }
    return parameter
}

function check_internal_ip(ip, origin_ip) {
    // If origin_ip is not empty and there is no non-intranet address, skip detection
    if (origin_ip && ! origin_ip.some(function(value) {
            return !internalRegex.test(value)
        })){ return }

    for (var i=0; i<ip.length; i++) {
        if (internalRegex.test(ip[i]))
        {
            return {
                action:     algorithmConfig.ssrf_userinput.action,
                message:    _("SSRF - Requesting intranet address: %1%", [ ip[i] ]),
                confidence: 100,
                algorithm:  'ssrf_userinput'
            }
        }
    }
}

function check_internal_hostname(hostname, origin_hostname) {
    if ((origin_hostname) && (origin_hostname == '[::]' || origin_hostname == '[::1]')) {
        return
    }
    if (hostname == '[::]' || hostname == '[::1]') 
    {
        return {
            action:     algorithmConfig.ssrf_userinput.action,
            message:    _("SSRF - Requesting intranet address: %1%", [ hostname ]),
            confidence: 100,
            algorithm:  'ssrf_userinput'
        }
    }
}

function check_internal(params, context, is_redirect) {
    var ret
    var all_parameter = get_all_parameter(context)
    if (is_redirect) {
        ret = check_internal_ip(params.ip, params.origin_ip)
        if (ret && !whiteHostName.test(params.hostname)) {return ret}
        ret = check_internal_hostname(params.hostname, params.origin_hostname)
        if (ret) {return ret}
    }
    else if (is_from_userinput(all_parameter, params.url)) {
        // non-redirect, determine user input
        ret = check_internal_ip(params.ip, undefined)
        if (ret && !whiteHostName.test(params.hostname)) {return ret}
        ret = check_internal_hostname(params.hostname, undefined)
        if (ret) {return ret}
    }
}

function check_ssrf(params, context, is_redirect) {
    var hostname  = params.hostname
    var url       = params.url
    var ip        = params.ip
    var reason    = false

    // Algorithm 1-When the parameter comes from user input and it is an intranet IP, it is judged as an SSRF attack
    if (algorithmConfig.ssrf_userinput.action != 'ignore')
    {
        var ret
        ret = check_internal(params, context, is_redirect)
        // Filter non-HTTP requests (dubbo)
        var header = context.header || {}
        if (ret && Object.keys(header).length != 0) {
            return ret
        }
    }

    // Algorithm 2-Check common detection domain names
    if (algorithmConfig.ssrf_common.action != 'ignore')
    {
        if (is_hostname_dnslog(hostname))
        {
            return {
                action:     algorithmConfig.ssrf_common.action,
                message:    _("SSRF - Requesting known DNSLOG address: %1%", [hostname]),
                confidence: 100,
                algorithm:  'ssrf_common'
            }
        }
    }

    // Algorithm 3-Detect AWS/Aliyun/GoogleCloud private address: two ways to intercept IP access and bind domain name access
    if (algorithmConfig.ssrf_aws.action != 'ignore')
    {
        if (ip == '169.254.169.254' || ip == '100.100.100.200'
            || hostname == '169.254.169.254' || hostname == '100.100.100.200' || hostname == 'metadata.google.internal')
        {
            return {
                action:     algorithmConfig.ssrf_aws.action,
                message:    _("SSRF - Requesting AWS metadata address"),
                confidence: 100,
                algorithm:  'ssrf_aws'
            }
        }
    }

    // Algorithm 4-ssrf_obfuscate
    //
    // Check for confusion:
    // http://2130706433
    // http://0x7f001
    //
    // The following obfuscation methods are not detected and are prone to false positives
    // http://0x7f.0x0.0x0.0x1
    // http://0x7f.0.0.0
    if (algorithmConfig.ssrf_obfuscate.action != 'ignore')
    {
        var reason = false

        if (!isNaN(hostname) && hostname.length != 0)
        {
            reason = _("SSRF - Requesting numeric IP address: %1%", [hostname])
        }
        // else if (hostname.startsWith('0x') && hostname.indexOf('.') === -1)
        // {
        //     reason = _("SSRF - Requesting hexadecimal IP address: %1%", [hostname])
        // }

        if (reason)
        {
            return {
                action:     algorithmConfig.ssrf_obfuscate.action,
                message:    reason,
                confidence: 100,
                algorithm:  'ssrf_obfuscate'
            }
        }
    }

    // Algorithm 5-special protocol check
    if (algorithmConfig.ssrf_protocol.action != 'ignore')
    {
        // Get agreement
        var proto = url.split(':')[0].toLowerCase()

        if (algorithmConfig.ssrf_protocol.protocols.indexOf(proto) != -1)
        {
            return {
                action:     algorithmConfig.ssrf_protocol.action,
                message:    _("SSRF - Using dangerous protocol: %1%://", [proto]),
                confidence: 100,
                algorithm:  'ssrf_protocol'
            }
        }
    }
    return false
}


// The next version will support translation, and currently it is necessary to expose a getText interface to the plugin
function _(message, args) 
{
    args = args || []

    for (var i = 0; i < args.length; i ++) 
    {
        var symbol = '%' + (i + 1) + '%'
        message = message.replace(symbol, args[i])
    }

    return message
}

// 开始

// If logging is enabled, print the log first, and then execute the subsequent logic
if (algorithmConfig.meta.log_event) {

    plugin.register('directory', function (params, context) {
        plugin.log('Listing directory content: ' + params.realpath, params.stack)
        return clean
    })

    plugin.register('fileUpload', function (params, context) {
        plugin.log('File upload: ' + params.filename)
        return clean
    })

    plugin.register('rename', function (params, context) {
        plugin.log('Rename file - From ' + params.source + ' to ' + params.dest)  
        return clean
    })

    plugin.register('ssrf', function (params, context) {
        plugin.log('SSRF requesting ' + params.url + ' (IP: ' + params.ip + ')')
        return clean
    })

    plugin.register('command', function (params, context) {
        plugin.log('Execute command: ' + params.command, params.stack)
        return clean
    })

    plugin.register('ognl', function (params, context) {
        plugin.log('Evaluating OGNL expression: ' + params.expression)
        return clean
    })

    plugin.register('xxe', function (params, context) {
        plugin.log('Loading XML entity: ' + params.entity)
        return clean
    })

    plugin.register('eval', function (params, context) {
        plugin.log('Evaluating code: ' + params.code)
        return clean
    })

    plugin.register('loadLibrary', function (params, context) {
        plugin.log('Loading library: ' + params.path)
        return clean
    })

    plugin.register('include', function (params, context) {
        plugin.log('Include file: ' + params.url)
        return clean
    })

    plugin.register('readFile', function (params, context) {
        plugin.log('Read file: ' + params.realpath)
        return clean
    })

    plugin.register('writeFile', function (params, context) {
        plugin.log('Write file: ' + params.realpath)
        return clean
    })

    plugin.register('sql', function (params, context) {
        plugin.log('SQL query: ' + params.query)
        return clean
    })
}


// If "R&D Mode" is turned on, only JS plugins will be used
if (! algorithmConfig.meta.is_dev && RASP.get_jsengine() !== 'v8') {
    // Before v1.1, SQL/SSRF was implemented natively by java, and the plug-in configuration needs to be passed to java
    // Before v1.0 RC1, RASP.config_set still needs to be used to pass configuration
    if (RASP.config_set) {
        RASP.config_set('algorithm.config', JSON.stringify(algorithmConfig))
    }
    //For v1.0 rhino
    Object.values = function (obj){
        var result = Array()
        for (key in obj) {
            result.push(obj[key])
        }
        return result
    }
} else {
 // For PHP + V8, the performance is not bad, we keep the JS detection logic
    plugin.register('sql', function (params, context) {

        var reason          = false
        var min_length      = algorithmConfig.sql_userinput.min_length
        var allow_full      = algorithmConfig.sql_userinput.allow_full
        var parameters      = context.parameter || {}
        var json_parameters = context.json || {}
        var raw_tokens      = []

        function _run(values, name) {
            var reason = false
            values.some(function (value) {
                //Do not handle arrays of 3 dimensions and above
                if (typeof value != "string") {
                    return false
                }

                //Minimum length limit
                if (value.length < min_length) {
                    return false
                }
// Use lcs to find or directly find
                if (algorithmConfig.sql_userinput.lcs_search) {
                    check_value = lcs_search(params.query, value)
                }
                else{
                    check_value = [value]
                }

                // Check if user input exists in SQL
                for(var i = 0, len = check_value.length; i < len; i++) {
                    value = check_value[i]

                    // Filter ultra-short parameters
                    if (value.length < 3) {
                        continue
                    }
                
                    var userinput_idx = params.query.indexOf(value)
                    if (userinput_idx == -1) {
                        return false
                    }

                    //If you allow the database manager
                    if (allow_full && params.query.length == value.length)
                    {
                        return false
                    }

                    // Filter known false positives
                    // 1,2,3,4,5 and user_id, user_name, user_pass
                    if (commaSeparatedRegex.test(value)) {
                        return false
                    }

                   // Pre-filtering regularity, if enabled
                    if (algorithmConfig.sql_userinput.pre_enable && ! sqliPrefilter1.test(value)) {
                        return false
                    }

                    // Lazy loading, initialize token when needed
                    if (raw_tokens.length == 0) {
                        raw_tokens = RASP.sql_tokenize(params.query, params.server)
                    }

                    //distance is used to shield the identifier token parsing false positive `dbname`.`table`, please delete it after version 1.2
                    var distance = 2
                    if (value.length > 20) {
                        distance = 3
                    }
                    if (is_token_changed(raw_tokens, userinput_idx, value.length, distance, is_sql=true)) {
                        reason = _("SQLi - SQL query structure altered by user input, request parameter name: %1%, value: %2%", [name, value])
                        return true
                    }
                }
            })
            return reason
        }

        // Algorithm 1: Match user input and simply identify whether the logic has changed
        if (algorithmConfig.sql_userinput.action !='ignore') {
            // match GET/POST/multipart parameters
            Object.keys(parameters).some(function (name) {
                // Cover the scene, the latter is only supported by PHP
                // ?id=XXXX
                // ?data[key1][key2]=XXX
                var value_list = []
                Object.values(parameters[name]).forEach(function (value){
                    if (typeof value == 'string') {
                        value_list.push(value)
                    } else {
                        value_list = value_list.concat(Object.values(value))
                    }
                })
                reason = _run(value_list, name)
                if (reason) {
                    return true
                }
            })

            // match header parameter
            if (reason == false && context.header != null) {
                Object.keys(context.header).some(function (name) {
                    if ( name.toLowerCase() == "cookie") {
                        var cookies = get_cookies(context.header.cookie)
                        for (name in cookies) {
                            reason = _run([cookies[name]], "cookie:" + name)
                            if (reason) {
                                return true
                            }
                        }
                    }
                    else if ( headerInjection.indexOf(name.toLowerCase()) != -1) {
                        reason = _run([context.header[name]], "header:" + name)
                        if (reason) {
                            return true
                        }
                    }
                    
                })
            }

           // Match json parameters
            if (reason == false && Object.keys(json_parameters).length > 0) {
                var jsons = [ [json_parameters, "input_json"] ]
                while (jsons.length > 0 && reason === false) {
                    var json_arr = jsons.pop()
                    var crt_json_key = json_arr[1]
                    var json_obj = json_arr[0]
                    for (item in json_obj) {
                        if (typeof json_obj[item] == "string") {
                            reason = _run([json_obj[item]], crt_json_key + "->" + item)
                            if(reason !== false) {
                                break;
                            }
                        }
                        else if (typeof json_obj[item] == "object") {
                            jsons.push([json_obj[item], crt_json_key + "->" + item])
                        }
                    }
                }
            }

            if (reason !== false && !sqliWhiteManager.test(params.stack[0])) {
                return {
                    action:     algorithmConfig.sql_userinput.action,
                    confidence: 90,
                    message:    reason,
                    algorithm:  'sql_userinput'
                }
            }
        }

      // Algorithm 2: SQL statement policy check (simulate SQL firewall function）
        if (algorithmConfig.sql_policy.action != 'ignore') {

            // Lazy loading, processing only when needed
            if ((raw_tokens.length == 0) && 
                (sqliPrefilter2.test(params.query))) {
                raw_tokens = RASP.sql_tokenize(params.query, params.server)
            }

            var features        = algorithmConfig.sql_policy.feature
            var func_list       = algorithmConfig.sql_policy.function_blacklist
            var func_count_list = algorithmConfig.sql_policy.function_count

            // blacklist function count
            var func_count_arr  = {}

            // Convert lowercase, avoid case bypass
            var tokens_lc = raw_tokens.map(function(v) {
                return v.text.substr(0, 50).toLowerCase()
            })

            //Is it in the union select statement
            var union_state = false

            for (var i = 1; i < tokens_lc.length; i ++)
            {
                if (features['union_null']) 
                {
                    if (tokens_lc[i] === 'union')
                    {
                        union_state = true
                    }
                    else if (tokens_lc[i] === 'from')
                    {
                        union_state = false
                    }
                    else if (tokens_lc[i] === 'select' && union_state)
                    {
                        var null_count = 0
                        var num_count = 0
// Find consecutive commas, NULLs or numbers
                        for (var j = i + 1; j < tokens_lc.length && j < i + 6; j ++) {
                            if ((tokens_lc[j] === ',' || tokens_lc[j] == 'null') && tokens_lc[j] != tokens_lc[j+1]) {
                                null_count ++
                            } else {
                                break
                            }
                        }
                        for (var j = i + 1; j < tokens_lc.length && j < i + 6; j ++) {
                            if ((tokens_lc[j] === ',' || ! isNaN(parseInt(tokens_lc[j]))) && tokens_lc[j] != tokens_lc[j+1]) {
                                num_count++
                            } else {
                                break
                            }
                        }

                        // NULL,NULL,NULL == 5个token
                        // 1,2,3          == 5个token
                        if (null_count >= 5 || num_count >= 5) {
                            reason = _("SQLi - Detected UNION-NULL phrase in sql query")
                            break
                        }
                        continue
                    }
                }

                if (features['stacked_query'] && tokens_lc[i] == ';' && i != tokens_lc.length - 1)
                {
                    reason = _("SQLi - Detected stacked queries")
                    break
                }
                else if (features['no_hex'] && tokens_lc[i][0] === '0' && tokens_lc[i][1] === 'x')
                {
                    reason = _("SQLi - Detected hexadecimal values in sql query")
                    break
                }
                else if (features['version_comment'] && tokens_lc[i][0] === '/' && tokens_lc[i][1] === '*' && tokens_lc[i][2] === '!')
                {
                    reason = _("SQLi - Detected MySQL version comment in sql query")
                    break
                }
                else if (features['function_blacklist'] && i > 0 && tokens_lc[i][0] === '(')
                {
                    var func_name = tokens_lc[i - 1]
                    if (func_list[func_name])
                    {
                        reason = _("SQLi - Detected dangerous method call %1%() in sql query", [func_name])
                        break
                    }

                    if (features['function_count'] && func_count_list[func_name])
                    {
                        if (! func_count_arr[func_name])
                        {
                            func_count_arr[func_name] = 1
                        }
                        else
                        {
                            func_count_arr[func_name] ++
                        }

                        //Exceeded the number of interceptions
                        if (func_count_arr[func_name] >= func_count_list[func_name]) 
                        {
                            reason = _("SQLi - Detected multiple call to dangerous method %1%() in sql query (%2% times)", [func_name, func_count_arr[func_name]])
                            break
                        }
                    }
                }            
                else if (features['into_outfile'] && i < tokens_lc.length - 2 && tokens_lc[i] == 'into')
                {
                    if (tokens_lc[i + 1] == 'outfile' || tokens_lc[i + 1] == 'dumpfile')
                    {
                        reason = _("SQLi - Detected INTO OUTFILE phrase in sql query")
                        break
                    }
                }
                else if (features['information_schema'] && i < tokens_lc.length - 1 && tokens_lc[i] == 'from')
                {
                    // `information_schema`.tables
                    // information_schema  .tables
                    var part = tokens_lc[i + 1].replaceAll('`', '', 40)
                  // Normal antlr and flex return 1 token
                    if (part == 'information_schema.tables')
                    {
                        reason = _("SQLi - Detected access to MySQL information_schema.tables table")
                        break
                    }
                    // flex will generate 3 tokens before 1.1.2
                    else if (part == 'information_schema' && i < tokens_lc.length - 3)
                    {
                        var part2 = tokens_lc[i + 3].replaceAll('`', '', 10)
                        if (part2 == "tables")
                        {
                            reason = _("SQLi - Detected access to MySQL information_schema.tables table")
                            break
                        }
                    }
                }
            }

            if (reason !== false && !sqliWhiteManager.test(params.stack[0])) 
            {
                return {
                    action:     algorithmConfig.sql_policy.action,
                    message:    reason,
                    confidence: 100,
                    algorithm:  'sql_policy'
                }
            }
        }

        // Algorithm 4: SQL regular expression
        if (algorithmConfig.sql_regex.action != 'ignore') {
            var regex_filter = new RegExp(algorithmConfig.sql_regex.regex, 'i')
            
            if (regex_filter.test(params.query)) {
                return {
                    action:     algorithmConfig.sql_regex.action,
                    confidence: 60,
                    message:    reason,
                    algorithm:  'sql_regex'
                }
            }
        }

        // 加入缓存，对 prepared sql 特别有效
        return clean
    })

    plugin.register('ssrf', function(params, context) {
        var ret = check_ssrf(params, context, false)
        if (ret !== false) {
            return ret
        }
        return clean
    })

    plugin.register('ssrfRedirect', function(params, context) {
        var params2 = {
            // Use the original url to detect user input
            origin_hostname: params.hostname,
            origin_ip: params.ip,

            url: params.url2,
            hostname: params.hostname2,
            ip: params.ip2,
            port: params.port2,
            function: params.function,
            stack: params.stack
        }
        var ret2 = check_ssrf(params2, context, true)
        if (ret2 !== false) {
            ret = check_ssrf(params, context, false)
            if (ret === false) {
                return ret2
            }
        }
        return clean
    })
}

plugin.register('sql_exception', function(params, context) {
    // In order to improve efficiency, abnormal codes are filtered on the agent side, and the plug-in is only responsible for filtering out possible false positives and splicing messages, e.g
    // mysql error 1367 detected: XXX
    var error_code = parseInt(params.error_code)
    var message    = _("%1% error %2% detected: %3%", [params.server, params.error_code, params.error_msg])
    // filter phpmyadmin
    if (sqliWhiteManager.test(params.stack[0])) {
        return clean
    }
    if (params.server == "mysql") {
        // 1062 Duplicated key error will cause a lot of false positives, only when the sentence contains the word rand, it will alarm
        if (error_code == 1062) {
            // Ignore case matching
            if ( !/rand/i.test(params.query)) {
                return clean
            }
        }
        
        else if (error_code == 1064) {
            if ( /in\s*(\(\s*\)|[^\(\w])/i.test(params.query)) {
                return clean
            }
            // Filter non-syntax errors
            if (! /syntax/i.test(params.error_msg)) {
                return clean
            }
        }
    }
    else if (params. server = 'sqlite') {
        if (error_code == 1) {
            //Case matching is ignored
            if ( ! /syntax/i. test(params. error_msg) && ! /malformed MATCH/i. test(params. error_msg)) {
                return clean
            }
        }
    }
    return {
        action:     algorithmConfig.sql_exception.action,
        message:    message,
        confidence: 70,
        algorithm:  'sql_exception'
    }
})

plugin.register('directory', function (params, context) {

    var realpath    = params.realpath
    var server      = context.server

    var is_windows  = server.os.indexOf('Windows') != -1
    var language    = server.language

    //Algorithm 2-Check for backdoors such as PHP choppers
    if (algorithmConfig.directory_reflect.action != 'ignore')
    {
        if (language == 'php' && validate_stack_php(params.stack))
        {
            return {
                action:     algorithmConfig.directory_reflect.action,
                message:    _("WebShell activity - Using file manager function with China Chopper WebShell"),
                confidence: 90,
                algorithm:  'directory_reflect'
            }
        }
        else if (language == 'java' && validate_stack_java(params.stack))
        {
            return {
                action:     algorithmConfig.directory_reflect.action,
                message:    _("WebShell activity - Using file manager function with Java WebShell"),
                confidence: 90,
                algorithm:  'directory_reflect'
            }
        }
    }
// Algorithm 1-User input matches.
    if (algorithmConfig.directory_userinput.action != 'ignore')
    {
       var all_parameter = get_all_parameter(context)

        if (is_path_containing_userinput(all_parameter, params.path, is_windows, algorithmConfig.directory_userinput.lcs_search))
        {
            return {
                action:     algorithmConfig.directory_userinput.action,
                message:    _("Path traversal - Accessing folder specified by userinput, folder is %1%", [realpath]),
                confidence: 90,
                algorithm:  'directory_userinput'
            }
        }
    }
// Algorithm 3-read sensitive directories
    if (algorithmConfig.directory_unwanted.action != 'ignore')
    {
        for (var i = 0; i < forcefulBrowsing.unwantedDirectory.length; i ++) {
            if (realpath == forcefulBrowsing.unwantedDirectory[i]) {
                return {
                    action:     algorithmConfig.directory_unwanted.action,
                    message:    _("WebShell activity - Accessing sensitive folder: %1%", [realpath]),
                    confidence: 100,
                    algorithm:  'directory_unwanted'
                }
            }
        }
    }

    return clean
})


plugin.register('readFile', function (params, context) {
    var server    = context.server
    var is_win    = server.os.indexOf('Windows') != -1

    // Under weblogic/tongweb, all war package read operations are ignored
    if (server['server'] === 'weblogic' || server['server'] == 'tongweb')
    {
        if (params.realpath.endsWith('.war') || params.realpath.endsWith('.ear'))
        {
            return clean;
        }
    }

    //Get agreement, if any
    var path_parts = params.path.split('://')
    var proto = ""
    if (path_parts.length > 1) {
        proto = path_parts[0].toLowerCase()
    }

    //
    //Algorithm 1: Simple user input recognition, intercept arbitrary file download vulnerabilities
    //
    // Does not affect normal operation, e.g
    // ?path=download/1.jpg
    //
    if (algorithmConfig.readFile_userinput.action != 'ignore')
    {
        var all_parameter = get_all_parameter(context)

        // ?path=/etc/./hosts
        // ?path=../../../etc/passwd
        if ( (proto == "" || proto == "file" ) && 
             !readFileWhiteExt.test(params.realpath) &&
             is_path_endswith_userinput(all_parameter, params.path, params.realpath, is_win, algorithmConfig.readFile_userinput.lcs_search)
           )
        {
            return {
                action:     algorithmConfig.readFile_userinput.action,
                message:    _("Path traversal - Downloading files specified by userinput, file is %1%", [params.realpath]),
                confidence: 90,
                algorithm: 'readFile_userinput'
            }
        }
        // @FIXME: User input is matched twice, and efficiency needs to be improved
        if (is_from_userinput(all_parameter, params.path))
        {
            //1. Read http(s):// content
            // ?file=http://www.baidu.com
            if (proto === 'http' || proto === 'https')
            {
                if (algorithmConfig.readFile_userinput_http.action != 'ignore')
                {
                    return {
                        action:     algorithmConfig.readFile_userinput_http.action,
                        message:    _("SSRF - Requesting http/https resource with file streaming functions, URL is %1%", [params.path]),
                        confidence: 90,
                        algorithm:  'readFile_userinput_http'
                    }
                }
            }

       // 2. Read special protocol content
            // ?file=file:///etc/passwd
            // ?file=php://filter/read=convert.base64-encode/resource=XXX
            if (proto === 'file' || proto === 'php')
            {
                if (algorithmConfig.readFile_userinput_unwanted.action != 'ignore')
                {
                    return {
                        action:     algorithmConfig.readFile_userinput_unwanted.action,
                        message:    _("Path traversal - Requesting unwanted protocol %1%://", [proto]),
                        confidence: 90,
                        algorithm:  'readFile_userinput_unwanted'
                    }
                }
            }
        }
    }

    //
// Algorithm 2: File, directory probe
    // If the application reads a file in the list, such as /root/.bash_history, this usually means a backdoor operation
    //
    if (algorithmConfig.readFile_unwanted.action != 'ignore')
    {
        var realpath_lc = params.realpath.toLowerCase()
        for (var j = 0; j < forcefulBrowsing.absolutePaths.length; j ++) {
            if (forcefulBrowsing.absolutePaths[j] == realpath_lc) {
                return {
                    action:     algorithmConfig.readFile_unwanted.action,
                    message:    _("WebShell activity - Accessing sensitive file %1%", [params.realpath]),
                    confidence: 90,
                    algorithm:  'readFile_unwanted'
                }
            }
        }
    }

    //
    // Algorithm 3: Check the file traversal to see if it exceeds the scope of the web directory [easy to misreport~]
    //
    if ( (proto == "" || proto == "file" ) && algorithmConfig.readFile_outsideWebroot.action != 'ignore')
    {
        var path        = params.path
        var appBasePath = context.appBasePath

        if (is_outside_webroot(appBasePath, params.realpath, path)) {
            return {
                action:     algorithmConfig.readFile_outsideWebroot.action,
                message:    _("Path traversal - accessing files outside webroot (%1%), file is %2%", [appBasePath, params.realpath]),
                confidence: 90,
                algorithm:  'readFile_outsideWebroot'
            }
        }
    }


    return clean
})

plugin.register('include', function (params, context) {
    var url       = params.url
    var server    = context.server
    var is_win    = server.os.indexOf('Windows') != -1
    var realpath  = params.realpath

    // User input check
    // ?file=/etc/passwd
    // ?file=../../../../../var/log/httpd/error.log
    if (algorithmConfig.include_userinput.action != 'ignore')
    {
        var all_parameter = get_all_parameter(context)

        if (is_path_endswith_userinput(all_parameter, url, realpath, is_win, algorithmConfig.include_userinput.lcs_search))
        {
            return {
                action:     algorithmConfig.include_userinput.action,
                message:    _("File inclusion - including files specified by user input"),
                confidence: 100,
                algorithm:  'include_userinput'
            }
        }
    }

    // if there is an agreement
    // include ('http://xxxxx')
    var items = url.split('://')
    var proto = items[0].toLowerCase()

  // special agreement,
    // include('file://XXX')
    // include('php://XXX')
    if (algorithmConfig.include_protocol.action != 'ignore')
    {
        if (algorithmConfig.include_protocol.protocols.indexOf(proto) != -1)
        {
            return {
                action:     algorithmConfig.include_protocol.action,
                message:    _("File inclusion - using unwanted protocol '%1%://' with funtion %2%()", [proto, params.function]),
                confidence: 90,
                algorithm:  'include_protocol'
            }
        }
    }

    return clean
})

plugin.register('writeFile', function (params, context) {

// Write NTFS stream files, usually to bypass restrictions
    if (algorithmConfig.writeFile_NTFS.action != 'ignore')
    {
        if (ntfsRegex.test(params.realpath))
        {
            return {
                action:     algorithmConfig.writeFile_NTFS.action,
                message:    _("File write - Writing NTFS alternative data streams", [params.realpath]),
                confidence: 95,
                algorithm:  'writeFile_NTFS'
            }
        }
    }

  // PUT upload script file-there is a related problem that needs to be solved, comment out temporarily
    // if (context.method == 'put' &&
    //     algorithmConfig.writeFile_PUT_script.action != 'ignore')
    // {
    //     if (scriptFileRegex.test(params.realpath))
    //     {
    //         return {
    //             action:     algorithmConfig.writeFile_PUT_script.action,
    //             message:    _("File upload - Using HTTP PUT method to upload a webshell", [params.realpath]),
    //             confidence: 95,
    //             algorithm:  'writeFile_PUT_script'
    //         }
    //     }
    // }

  // For this algorithm, please refer to this plugin customization document
    // https://rasp.baidu.com/doc/dev/official.html#case-file-write
    if (algorithmConfig.writeFile_script.action != 'ignore')
    {
        var all_parameter = get_all_parameter(context)
        var is_win = context.server.os.indexOf('Windows') != -1
        if (scriptFileRegex.test(params.realpath))
        {
            if (!(algorithmConfig.writeFile_script.userinput) ||
                ((algorithmConfig.writeFile_script.userinput) &&
                (is_path_endswith_userinput(all_parameter, params.path, params.realpath, is_win, algorithmConfig.writeFile_script.lcs_search)))
            ) {
                return {
                    action:     algorithmConfig.writeFile_script.action,
                    message:    _("File write - Creating or appending to a server-side script file, file is %1%", [params.realpath]),
                    confidence: 85,
                    algorithm:  'writeFile_script'
                }
            }
        }
    }

    if (algorithmConfig.writeFile_reflect.action != 'ignore') {
        if (context.server.language == 'java' && params.realpath.endsWith(".jsp")) {
            var message = validate_stack_java(params.stack)
            if (message) {
                return {
                    action:     algorithmConfig.writeFile_reflect.action,
                    message:    _("Reflect file write - %1%, file is %2%", [message, params.realpath]),
                    confidence: 85,
                    algorithm:  'writeFile_reflect'
                }
            }
        }
    }

    return clean
})

plugin.register('deleteFile', function (params, context) {

    if (algorithmConfig.deleteFile_userinput.action != 'ignore')
    {
        var all_parameter = get_all_parameter(context)
        var is_win = context.server.os.indexOf('Windows') != -1
        if (is_path_endswith_userinput(all_parameter, params.path, params.realpath, is_win, algorithmConfig.deleteFile_userinput.lcs_search)) {
            return {
                action:     algorithmConfig.deleteFile_userinput.action,
                message:    _("File delete - Deleting files specified by userinput, file is %1%", [params.realpath]),
                confidence: 85,
                algorithm:  'deleteFile_userinput'
            }
        }
    }
    return clean
})


plugin.register('fileUpload', function (params, context) {

   // Whether to prohibit the use of multipart to upload script files, or apache/php server configuration files
    if (algorithmConfig.fileUpload_multipart_script.action != 'ignore')
    {
        if (scriptFileRegex.test(params.filename) || ntfsRegex.test(params.filename))
        {
            return {
                action:     algorithmConfig.fileUpload_multipart_script.action,
                message:    _("File upload - Uploading a server-side script file with multipart/form-data protocol, filename: %1%", [params.filename]),
                confidence: 95,
                algorithm:  'fileUpload_multipart_script'
            }
        }

        if (params.filename == ".htaccess" || params.filename == ".user.ini")
        {
            return {
                action:     algorithmConfig.fileUpload_multipart_script.action,
                message:    _("File upload - Uploading a server-side config file with multipart/form-data protocol, filename: %1%", [params.filename]),
                confidence: 95,
                algorithm:  'fileUpload_multipart_script'
            }
        }
    }
// Whether to prohibit HTML/JS files, mainly to combat phishing, CORS bypass and other issues
    if (algorithmConfig.fileUpload_multipart_html.action != 'ignore')
    {
        if (htmlFileRegex.test(params.filename))
        {
            return {
                action:     algorithmConfig.fileUpload_multipart_html.action,
                message:    _("File upload - Uploading a HTML/JS file with multipart/form-data protocol, filename: %1%", [params.filename]),
                confidence: 90,
                algorithm:  'fileUpload_multipart_html'
            }
        }
    }

   // Whether to prohibit EXE/DLL files to prevent them from being used in backdoor download sites
    if (algorithmConfig.fileUpload_multipart_exe.action != 'ignore')
    {
        if (exeFileRegex.test(params.filename))
        {
            return {
                action:     algorithmConfig.fileUpload_multipart_exe.action,
                message:    _("File upload - Uploading a Executable file with multipart/form-data protocol, filename: %1%", [params.filename]),
                confidence: 90,
                algorithm:  'fileUpload_multipart_exe'
            }
        }
    }

    return clean
})



if (algorithmConfig.fileUpload_webdav.action != 'ignore')
{
    plugin.register('webdav', function (params, context) {
// The source file is not a script && The target file is a script, it is judged to write the backdoor in MOVE mode
        if (! scriptFileRegex.test(params.source) && scriptFileRegex.test(params.dest))
        {
            return {
                action:    algorithmConfig.fileUpload_webdav.action,
                message:   _("File upload - Uploading a server-side script file with HTTP method %1%, file is %2%", [
                    context.method, params.dest
                ]),
                confidence: 100,
                algorithm:  'fileUpload_webdav'
            }
        }

        return clean
    })
}

if (algorithmConfig.rename_webshell.action != 'ignore')
{
    plugin.register('rename', function (params, context) {
    // The target file is considered to be a backdoor in webroot
        if (!is_outside_webroot(context.appBasePath, params.dest, null)) {
      // The source file is a clean file, and the target file is a script file. It is judged to be a rename method to write a backdoor
            if (cleanFileRegex.test(params.source) && scriptFileRegex.test(params.dest))
            {
                return {
                    action:    algorithmConfig.rename_webshell.action,
                    message:   _("File upload - Renaming a non-script file to server-side script file, source file is %1%", [
                        params.source
                    ]),
                    confidence: 90,
                    algorithm:  'rename_webshell'
                }
            }
        }

        return clean
    })
}


if (algorithmConfig.link_webshell.action != 'ignore')
{
    plugin.register('link', function (params, context) {
      // The target file is considered to be a backdoor in webroot
        if (!is_outside_webroot(context.appBasePath, params.dest, null)) {
          // The source file is a clean file, and the target file is a script file. It is judged to be a rename method to write a backdoor
            if (cleanFileRegex.test(params.source) && scriptFileRegex.test(params.dest))
            {
                return {
                    action:    algorithmConfig.link_webshell.action,
                    message:   _("File upload - Linking a non-script file to server-side script file, source file is %1%, link type", [
                        params.source,
                        params.type
                    ]),
                    confidence: 90,
                    algorithm:  'link_webshell'
                }
            }
        }

        return clean
    })
}

plugin.register('command', function (params, context) {
    var cmd        = params.command
    var server     = context.server
    var message    = undefined
    var raw_tokens = []


    // Algorithm 1: According to the stack, check whether it is a deserialization attack.
    // In theory, this algorithm does not have false positives

    if (algorithmConfig.command_reflect.action != 'ignore') {
        //Java detection logic
        if (server.language == 'java') {
            message = validate_stack_java(params.stack)
            if (message) {
                message = _("Reflected command execution - %1%", [message])
            }
        }

     // PHP detection logic
        else if (server.language == 'php' && validate_stack_php(params.stack))
        {
            message = _("WebShell activity - Detected reflected command execution")
        }

        if (message)
        {
            return {
                action:     algorithmConfig.command_reflect.action,
                message:    message,
                confidence: 100,
                algorithm:  'command_reflect'
            }
        }
    }

// Starting from v0.31, when the command execution comes from a non-HTTP request, we will also detect deserialization attacks
    // But normal command execution should not be intercepted, so add a context.url check here
    if (! context.url) {
        return clean
    }

   // Algorithm 2: Detect command injection, or command execution backdoor
    if (algorithmConfig.command_userinput.action != 'ignore') {
        var reason     = false
        var min_length = algorithmConfig.command_userinput.min_length
        var parameters = context.parameter || {}
        var json_parameters = context.json || {}
        var unexploitable_filter = algorithmConfig.command_userinput.java_unexploitable_filter

        // Check whether the command logic is modified by user parameters
        function _run(values, name)
        {
            var reason = false

            values.some(function (value) {
                if (value.length <= min_length) {
                    return false
                }
                
                // Check if user input is present in the command
                var userinput_idx = cmd.indexOf(value)
                if (userinput_idx == -1) {
                    return false
                }

                if (cmd.length == value.length) {
                    reason = _("WebShell detected - Executing command: %1%", [cmd])
                    return true
                }
                
                // Lazy loading, initialize token when needed
                if (raw_tokens.length == 0) {
                    raw_tokens = RASP.cmd_tokenize(cmd)
                }

                if (is_token_changed(raw_tokens, userinput_idx, value.length)) {
                    reason = _("Command injection - command structure altered by user input, request parameter name: %1%, value: %2%", [name, value])
                    return true
                }
            })

            return reason
        }

      // filter command injection that java cannot use
        if (server.language != 'java' || !unexploitable_filter || cmdJavaExploitable.test(cmd)) {
           // match GET/POST/multipart parameters
            Object.keys(parameters).some(function (name) {
                // Cover the scene, the latter is only supported by PHP
                // ?id=XXXX
                // ?data[key1][key2]=XXX
                var value_list = []
                Object.values(parameters[name]).forEach(function (value){
                    if (typeof value == 'string') {
                        value_list.push(value)
                    } else {
                        value_list = value_list.concat(Object.values(value))
                    }
                })
                reason = _run(value_list, name)
                if (reason) {
                    return true
                }
            })
            // Match header parameter
            if (reason == false && context.header != null) {
                Object.keys(context.header).some(function (name) {
                    if ( name.toLowerCase() == "cookie") {
                        var cookies = get_cookies(context.header.cookie)
                        for (name in cookies) {
                            reason = _run([cookies[name]], "cookie:" + name)
                            if (reason) {
                                return true
                            }
                        }
                    }
                    else if ( headerInjection.indexOf(name.toLowerCase()) != -1) {
                        reason = _run([context.header[name]], "header:" + name)
                        if (reason) {
                            return true
                        }
                    }
                    
                })
            }

         // Match json parameters
            if (reason == false && Object.keys(json_parameters).length > 0) {
                var jsons = [ [json_parameters, "input_json"] ]
                while (jsons.length > 0 && reason === false) {
                    var json_arr = jsons.pop()
                    var crt_json_key = json_arr[1]
                    var json_obj = json_arr[0]
                    for (item in json_obj) {
                        if (typeof json_obj[item] == "string") {
                            reason = _run([json_obj[item]], crt_json_key + "->" + item)
                            if(reason !== false) {
                                break;
                            }
                        }
                        else if (typeof json_obj[item] == "object") {
                            jsons.push([json_obj[item], crt_json_key + "->" + item])
                        }
                    }
                }
            }
        }

        if (reason !== false)
        {
            return {
                action:     algorithmConfig.command_userinput.action,
                confidence: 90,
                message:    reason,
                algorithm:  'command_userinput'
            }
        }
    }

    // Algorithm 3: Common penetration commands
    if (algorithmConfig.command_common.action != 'ignore')
    {
        var reason = false
        if (cmdPostPattern.test(params.command))
        {           
            return {
                action:     algorithmConfig.command_common.action,
                message:    _("Webshell detected - Executing potentially dangerous command, command is %1%", [params.command]),
                confidence: 95,
                algorithm:  'command_common'
            }
        }     
    }

// Algorithm 4: Find syntax errors and sensitive operations
    if (algorithmConfig.command_error.action != 'ignore') {
        if (raw_tokens.length == 0) {
            raw_tokens = RASP.cmd_tokenize(cmd)
        }
        var concat_char = algorithmConfig.command_error.concat_char
        var sensitive_cmd = algorithmConfig.command_error.sensitive_cmd
        var alarm_token = algorithmConfig.command_error.alarm_token

        var double_quote = 0
        var ticks = 0
        for (var i=0; i<raw_tokens.length; i++) {
            //Sensitive token detection
            if (algorithmConfig.command_error.alarm_token_enable) {
                if (alarm_token == raw_tokens[i].text) {
                    if ( !(i > 0 && i < raw_tokens.length-1 && raw_tokens[i-1].text == '"' && raw_tokens[i+1].text == '"')) {
                        return {
                            action:     algorithmConfig.command_error.action,
                            confidence: 90,
                            message:    _("Command execution - Sensitive command token detect: %1%", [raw_tokens[i].text]),
                            algorithm:  'command_error'
                        }
                    }
                }
            }

            // Sensitive connection command detection
            if (algorithmConfig.command_error.sensitive_cmd_enable) {
                if (raw_tokens[i+1] !== undefined &&
                    concat_char.indexOf(raw_tokens[i].text) != -1 &&
                    sensitive_cmd.indexOf(raw_tokens[i+1].text) != -1) {
                    return {
                        action:     algorithmConfig.command_error.action,
                        confidence: 70,
                        message:    _("Command execution - Sensitive command concat detect: %1% %2%", [raw_tokens[i].text, raw_tokens[i+1].text]),
                        algorithm:  'command_error'
                    }
                }
            }

            if (raw_tokens[i].text == "\"") {
                double_quote ++
            }
            else if (raw_tokens[i].text == "`") {
                ticks ++
            }
            else if (raw_tokens[i].text == "'" && algorithmConfig.command_error.unbalanced_quote_enable) {
                if ( !(i > 0 && i < raw_tokens.length-1 && raw_tokens[i-1].text == '"' && raw_tokens[i+1].text == '"')) {
                    return {
                        action:     algorithmConfig.command_error.action,
                        confidence: 70,
                        message:    _("Command execution - Detected unbalanced single quote!"),
                        algorithm:  'command_error'
                    }
                }
            }
        }

        // Quotation mark mismatch detection
        if (algorithmConfig.command_error.unbalanced_quote_enable) {
            if (double_quote % 2 != 0) {
                return {
                    action:     algorithmConfig.command_error.action,
                    confidence: 70,
                    message:    _("Command execution - Detected unbalanced double quote!"),
                    algorithm:  'command_error'
                }
            }
            if (ticks % 2 != 0) {
                return {
                    action:     algorithmConfig.command_error.action,
                    confidence: 70,
                    message:    _("Command execution - Detected unbalanced backtick!"),
                    algorithm:  'command_error'
                }
            }
        }
    }

    // Algorithm 5: Record all command execution
    if (algorithmConfig.command_other.action != 'ignore') {
        return {
            action:     algorithmConfig.command_other.action,
            message:    _("Command execution - Logging all command execution by default, command is %1%", [params.command]),
            confidence: 90,
            algorithm:  'command_other'
        }
    }

    return clean
})

// Note: Because libxml2 cannot be hooked, PHP does not support XXE detection temporarily
plugin.register('xxe', function (params, context) {
    var server      = context.server
    var is_win      = server.os.indexOf('Windows') != -1
    var items       = params.entity.split('://')
    var parameters  = context.parameter || {}
    var header      = context.header || {}

    if (algorithmConfig.xxe_protocol.action != 'ignore') {
        // Check windows + SMB protocol to prevent leakage of NTLM information
        if (params.entity.startsWith('\\\\')) {
            return {
                action:     algorithmConfig.xxe_protocol.action,
                message:    _("XXE - Using dangerous protocol SMB"),
                confidence: 100,
                algorithm:  'xxe_protocol'
            }
        }
    }

    if (items.length >= 2) {
        var protocol = items[0].toLowerCase()
        var address  = items[1]

        // Reject special agreement
        if (algorithmConfig.xxe_protocol.action != 'ignore') {
            if (algorithmConfig.xxe_protocol.protocols.indexOf(protocol) != -1) {
                return {
                    action:     algorithmConfig.xxe_protocol.action,
                    message:    _("XXE - Using dangerous protocol %1%", [protocol]),
                    confidence: 100,
                    algorithm:  'xxe_protocol'
                }
            }

        }

        // file protocol + absolute path, e.g
        // file:///etc/passwd
        // file:///etc/passwd?a=1#b=2 (only Java support)
        //
        // Relative paths are prone to false positives, e.g
        // file://xwork.dtd
        if (algorithmConfig.xxe_file.action != 'ignore')
        {
            if (address.length > 0 && protocol === 'file' && is_absolute_path(address, is_win) )
            {
                var address_lc = address.toLowerCase()
                
                //1.0 Rhino engine does not support URL objects. Considering that there are not many users in 1.0, let’s deal with it briefly.
                try
                {
                    var urlObj = new URL(address_lc)
                    address_lc = urlObj.pathname
                }
                catch (e) {}
                var content_type = header["content-type"] || ""
                if (content_type.indexOf("xml") != -1 || is_include_in_userinput(parameters, address)) {
                    //Filter out xml, dtd
                    if (! address_lc.endsWith('.xml') &&
                        ! address_lc.endsWith('.dtd'))
                    {
                        return {
                            action:     algorithmConfig.xxe_file.action,
                            message:    _("XXE - Accessing file %1%", [address]),
                            confidence: 90,
                            algorithm:  'xxe_file'
                        }
                    }
                }
            }
        }

    }
    return clean
})


if (algorithmConfig.eval_regex.action != 'ignore')
{
	// Algorithm 1: Regular expression
    plugin.register('eval', function(params, context) {
        var regex_filter = new RegExp(algorithmConfig.eval_regex.regex, 'i')
            
        if (regex_filter.test(params.code)) {

        	// Avoid too long message
        	var code = params.code.substr(0, 50)
        	if (params.code.length > 50)
        	{
        		code = code + ' ...'
        	}

            return {
                action:     algorithmConfig.eval_regex.action,
                confidence: 60,
                message:    _("Code Execution - Running %1% with %2%() function", [code, params.function]),
                algorithm:  'eval_regex'
            }
        }
    })
}

plugin.register('loadLibrary', function(params, context) {

    if (algorithmConfig.loadLibrary_unc.action != 'ignore') {

        // Only windows need to check UNC
        var is_windows = context.server.os.indexOf('Windows') != -1
        if (is_windows) {
            if (params.path.startsWith('\\\\') || params.path.startsWith('//')) {
                return {
                    action:     algorithmConfig.loadLibrary_unc.action,
                    confidence: 60,
                    message:    _("Load library in UNC path - loading %1% with %2%() function", [params.path, params.function]),
                    algorithm:  'loadLibrary_unc'
                }
            }    
        }
        
    }

    // if (algorithmConfig.loadLibrary_other.action != 'ignore') {
    //     return {
    //         action:     algorithmConfig.loadLibrary_other.action,
    //         confidence: 60,
    //         message:    _("Load library - logging all by default, library path is %1%", [params.path]),
    //         algorithm:  'loadLibrary_other'
    //     }     
    // }

    return clean
})

if (algorithmConfig.ognl_exec.action != 'ignore')
{
    // By default, when the length of the OGNL expression exceeds 30, it will enter the detection point. This length can be configured
    plugin.register('ognl', function (params, context) {

        //Common struts payload statement characteristics
        var ognlPayloads = [
            'ognl.OgnlContext',
            'ognl.TypeConverter',
            'ognl.MemberAccess',
            '_memberAccess',
            'ognl.ClassResolver',
            'java.lang.Runtime',
            'java.lang.Class',
            'java.lang.ClassLoader',
            'java.lang.System',
            'java.lang.ProcessBuilder',
            'java.lang.Object',
            'java.lang.Shutdown',
            'java.io.File',
            'javax.script.ScriptEngineManager',
            'com.opensymphony.xwork2.ActionContext'
        ]

        var ognlExpression = params.expression
        for (var index in ognlPayloads)
        {
            if (ognlExpression.indexOf(ognlPayloads[index]) > -1)
            {
                return {
                    action:     algorithmConfig.ognl_exec.action,
                    message:    _("OGNL exec - Trying to exploit a OGNL expression vulnerability"),
                    confidence: 100,
                    algorithm:  'ognl_exec'
                }
            }

        }
        return clean
    })
}

if (algorithmConfig.deserialization_transformer.action != 'ignore') {

    plugin.register('deserialization', function (params, context) {
        var deserializationInvalidClazz = [
            'org.apache.commons.collections.functors.ChainedTransformer.transform',
            'org.apache.commons.collections.functors.InvokerTransformer',
            'org.apache.commons.collections.functors.InstantiateTransformer',
            'org.apache.commons.collections4.functors.InvokerTransformer',
            'org.apache.commons.collections4.functors.InstantiateTransformer',
            'org.codehaus.groovy.runtime.ConvertedClosure',
            'org.codehaus.groovy.runtime.MethodClosure',
            'org.springframework.beans.factory.ObjectFactory',
            'xalan.internal.xsltc.trax.TemplatesImpl'
        ]

        var clazz = params.clazz
        for (var index in deserializationInvalidClazz) {
            if (clazz === deserializationInvalidClazz[index]) {
                return {
                    action:     algorithmConfig.deserialization_transformer.action,
                    message:    _("Transformer deserialization - unknown deserialize vulnerability detected"),
                    confidence: 100,
                    algorithm:  'deserialization_transformer'
                }
            }
        }
        return clean
    })
}


// Match ID
function findFirstIdentityCard(data) {
    const regexChineseId = /(?<!\d)\d{10}(?:[01]\d)(?:[0123]\d)\d{3}(?:\d|x|X)(?!\d)/;
    const W = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    const m = regexChineseId.exec(data)
    if (m) {
        const id = m[0]
        let sum = 0;
        for (let i = 0; i < W.length; i++) {
            sum += (id[i] - '0') * W[i];
        }
        if (id[17] == 'X' || id[17] == 'x') {
            sum += 10;
        } else {
            sum += id[17] - '0';
        }
        if (sum % 11 == 1) {
            return {
                type:  'Identity Card',
                match: m[0],
                parts: data.slice(Math.max(m.index - 40, 0), m.index + m[0].length + 40)
            }
        }
    }
}

//Match phone number
function findFirstMobileNumber(data) {
    const regexChinesePhone = /(?<!\w)(?:(?:00|\+)?86 ?)?(1\d{2})(?:[ -]?\d){8}(?!\w)/;
    const prefixs = new Set([133, 149, 153, 173, 174, 177, 180,
        181, 189, 199, 130, 131, 132, 145, 146, 155, 156, 166, 175, 176, 185, 186, 134, 135, 136, 137, 138, 139,
        147, 148, 150, 151, 152, 157, 158, 159, 165, 178, 182, 183, 184, 187, 188, 198, 170
    ]);
    let m = regexChinesePhone.exec(data)
    if (m) {
        if (prefixs.has(parseInt(m[1]))) {
            return {
                type:  'Mobile Number',
                match: m[0],
                parts: data.slice(Math.max(m.index - 40, 0), m.index + m[0].length + 40)
            }
        }
    }
}

// Match bank card, credit card
function findFirstBankCard(data) {
    const regexBankCard = /(?<!\d)(?:62|3|5[1-5]|4\d)\d{2}(?:[ -]?\d{4}){3}(?!\d)/;
    let m = regexBankCard.exec(data)
    if (m) {
        let card = m[0].replace(/ |-/g, "");
        let len = card.length;
        let sum = 0;
        for (let i = len; i >= 1; i--) {
            let t = card[len - i] - '0';
            if (i % 2 == 0) {
                t *= 2;
            }
            sum = sum + Math.floor(t / 10) + t % 10;
        }
        if (sum % 10 == 0) {
            return {
                type:  'Bank Card',
                match: m[0],
                parts: data.slice(Math.max(m.index - 40, 0), m.index + m[0].length + 40)
            }
        }
    }
}

if (algorithmConfig.response_dataLeak.action != 'ignore') {

    //response All test points will be sampled
    plugin.register('response', function (params, context) {
        const content_type = params.content_type
        const content      = params.content
        const kind         = algorithmConfig.response_dataLeak.kind
        const header       = context.header || {}

        var items = [], parts = []

       // content-type filtering
        if ( ! content_type && ! dataLeakContentType.test(content_type)) {
            return clean
        }

        // Whether to check the ID card leak
        if (kind.identity_card) {
            const data = findFirstIdentityCard(content)
            if (data) {
                items.push(data.match + '(' + data.type + ')')
                parts.push(data)
            }
        }

        // Whether to check the phone number leak
        if (kind.phone) {
            const data = findFirstMobileNumber(content)
            if (data) {
                items.push(data.match + '(' + data.type + ')')
                parts.push(data)
            }
        }

     // Whether to check bank card leakage
        if (kind.bank_card) {
            const data = findFirstBankCard(content)
            if (data) {
                items.push(data.match + '(' + data.type + ')')
                parts.push(data)
            }
        }

        if (items.length) {
            return {
                action:     algorithmConfig.response_dataLeak.action,
                message:    'PII leak detected: ' + items.join('、 '),
                confidence: 80,
                algorithm:  'response_dataLeak',
                params: {
                    parts
                }
            }
        }
    })
}

plugin.log('OpenRASP official plugin: Initialized, version', plugin_version)

