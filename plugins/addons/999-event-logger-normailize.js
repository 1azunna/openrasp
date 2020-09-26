const plugin_version = '2018-1000-1000'
const plugin_name    = 'event-logger-normalize'
const plugin_desc    = 'Event recorder plugin (normalized SQL)'

//
// OpenRASP plugin: event logger - normalize SQL phrase
// 

'use strict'
var plugin  = new RASP(plugin_name)

const clean = {
    action:     'ignore',
    message:    'Looks fine to me',
    confidence: 0
}

// BEGIN ALGORITHM CONFIG //

var algorithmConfig = {}

// END ALGORITHM CONFIG //

plugin.register('directory', function (params, context) {
    plugin.log('Listing directory content: ' + params.realpath)
    return clean
})

plugin.register('webdav', function (params, context) {
    plugin.log('Webdav operation: ', context.method, params.source, params.dest)
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

plugin.register('command', function (params, context) {
    plugin.log('Execute command: ' + params.command)
    return clean
})

// In order to improve performance, only when the length of the OGNL expression exceeds 30, the plugin will be called
// This 30 can be configured, aka "ognl.expression.minlength"
// https://rasp.baidu.com/doc/setup/others.html
plugin.register('ognl', function (params, context) {
    plugin.log('Evaluating OGNL expression: ' + params.expression)
    return clean
})

// The following methods may generate a lot of logs
plugin.register('xxe', function (params, context) {
    plugin.log('Loading XML entity: ' + params.entity)
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

function normalize_query(query) {
    var tokens = RASP.sql_tokenize(query)
    for (var i = 0; i < tokens.length; i ++) {
        var token = tokens[i]

        // Check if it is a string
        if ( (token[0] == "'" || token[0] == '"') &&
            (token[token.length - 1] == "'" || token[token.length - 1] == '"'))
        {
            tokens[i] = '"S"'
        }
    }

    return tokens.join(' ')
}

// Recording SQL logs may bring the following two problems
// 1. The query statement may contain sensitive information
// 2. The amount of logs may be large
plugin.register('sql', function (params, context) {
    plugin.log('SQL query: ' + normalize_query(params.query))
    return clean
})

plugin.log('999-event-logger: plugin loaded')


