const plugin_version = '2018-1000-1000'
const plugin_name    = 'event-logger'
const plugin_desc    = 'Event recorder plugin'

//
// OpenRASP plugin: event logger
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

plugin.register('ssrf', function (params, context) {
    plugin.log('SSRF requesting ' + params.url + ' (IP: ' + params.ip + ')')
    return clean
})

plugin.register('command', function (params, context) {
    plugin.log('Execute command: ' + params.command)
    return clean
})

// In order to improve performance, the plug-in will be called only when the length of the OGNL expression exceeds 30
// This 30 can be configured, aka "ognl.expression.minlength"
// https://rasp.baidu.com/doc/setup/others.html
plugin.register('ognl', function (params, context) {
    plugin.log('Evaluating OGNL expression: ' + params.expression)
    return clean
})

//The following methods may generate a lot of logs
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

plugin.register('requestEnd', function (params, context) {
    plugin.log('At requestEnd')
    return clean
})

plugin.log('999-event-logger: plugin loaded')


