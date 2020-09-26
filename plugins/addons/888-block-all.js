const plugin_version = '2018-1000-1000'
const plugin_name    = '888-block-all'

// This plugin is used to test the interception effect
//
// The logic of this plugin is to intercept all requests regardless of whether the request is normal or not
// To open this plugin, please delete the following throw first :-)
throw new Error("This plugin will block all operations, in order to prevent misoperation, please delete this line")

'use strict'
var plugin  = new RASP('block-all-test')

const default_action = {
    action:     'block',
    message:    '-All plug-ins intercept test-',
    confidence: 90
}

// BEGIN ALGORITHM CONFIG //

var algorithmConfig = {}

// END ALGORITHM CONFIG //

plugin.register('sql', function (params, context) {
    return default_action
})

plugin.register('ssrf', function (params, context) {
    return default_action
})

plugin.register('directory', function (params, context) {
    return default_action
})

plugin.register('readFile', function (params, context) {
    return default_action
})

plugin.register('webdav', function (params, context) {
    return default_action
})

plugin.register('include', function (params, context) {
    return default_action
})

plugin.register('writeFile', function (params, context) {
    return default_action
})

plugin.register('fileUpload', function (params, context) {
    return default_action
})

plugin.register('command', function (params, context) {
    return default_action
})

// Note: PHP does not support XXE detection
plugin.register('xxe', function (params, context) {
    return default_action
})

//By default, when the length of the OGNL expression exceeds 30, it will enter the detection point. This length can be configured
plugin.register('ognl', function (params, context) {
    return default_action
})

// [[Recently adjusted~ ]]
plugin.register('deserialization', function (params, context) {
    return default_action
})

plugin.log('All intercept plug-in tests: Initialization successful')
