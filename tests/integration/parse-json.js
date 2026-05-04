'use strict'

var readline = require('readline');
var rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

function sortKeys (value) {
  if (value === null || typeof value !== 'object') {
    return value
  }
  if (Array.isArray(value)) {
    return value.map(sortKeys)
  }
  var sorted = {}
  Object.keys(value).sort().forEach(function (key) {
    sorted[key] = sortKeys(value[key])
  })
  return sorted
}

rl.on('line', function(line){
    try {
      const obj = JSON.parse(line)
      console.log(JSON.stringify(sortKeys(obj), null, 2))
    } catch (e) {
      console.log(line)
    }
})
