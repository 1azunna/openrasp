const plugin_version = '2018-1000-1000'
const plugin_name    = '002-detect-scanner'

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
  // Known scanner recognition
  var foundScanner = false
  var scannerUA    = [
    "attack", "scan", "vulnerability", "injection", "xss",
    "exploit", "grabber", "cgichk", "bsqlbf", "sqlmap", 
    "nessus", "arachni", "metis", "sql power injector", 
    "bilbo", "absinthe", "black widow", "n-stealth", "brutus", 
    "webtrends security analyzer", "netsparker", "jaascois", "pmafind", 
    ".nasl", "nsauditor", "paros", "dirbuster", "pangolin", "nmap nse", 
    "sqlninja", "nikto", "webinspect", "blackwidow", "grendel-scan", 
    "havij", "w3af", "hydra"]
  var headers      = context.header

  if (headers['acunetix-product'] || headers['x-wipp']) {
    foundScanner = true
  } else {
    var ua = headers['user-agent']
    if (ua) {
      for (var i = 0; i < scannerUA.length; i++) {
        if (ua.indexOf(scannerUA[i].toLowerCase()) != -1) {
          foundScanner = true
          break
        }
      }
    }
  }
  // Scanner recognizes DEMO //    
  if (foundScanner) {
    return {
      action:     'block',
      message:    'Known scanner detection behavior, UA characteristics are: ' + scannerUA[i],
      confidence: 90
    }
  }
  return clean
})

plugin.log('002-detect-scanner loading completed')

