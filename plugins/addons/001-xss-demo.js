const plugin_version = '2018-1000-1000'
const plugin_name    = '001-xss-demo'

// This demo plugin has been abandoned
//
// The Java version can only be used after setting request.param_encoding
// The PHP version does not support request hook points, so there is no such detection//  
//  https://rasp.baidu.com/doc/setup/others.html

var plugin = new RASP(plugin_name)
var clean  = {
    action: 'ignore',
    message: 'no risk',
    confidence: 0
}

// BEGIN ALGORITHM CONFIG //

var algorithmConfig = {}

// END ALGORITHM CONFIG //

plugin.register('request', function(params, context) {

   // XSS detection DEMO
    // Simply match user input parameters at request hook
    function detectXSS(params, context) {
        var xssRegex   = /<script|script>|<iframe|iframe>|javascript:(?!(?:history\.(?:go|back)|void\(0\)))/i
        var parameters = context.parameter;
        var message    = '';

        Object.keys(parameters).some(function (name) {
            parameters[name].some(function (value) {
                if (xssRegex.test(value)) {
                    message = 'XSS attack: ' + value;
                    return true;
                }
            });

            if (message.length) {
                return true;
            }
        });

        return message
    }

   // XSS detection DEMO //
    var message = detectXSS(params, context)
    if (message.length) {
        return {
            action:     'block',
            message:    message,
            confidence: 90
        }
    }

    return clean    
})

plugin.log('001-xss-demo loading completed')

