
/// <reference path='../../../../src/compiler/typecheck/sound/rt.ts' />

/// <reference path="../scripts-ts/qunit/qunit.d.ts" />
/// <reference path="../scripts-ts/qunit/qunit-1.14.0.ts" />

//var _testDone = function (result) { }
var _testDone = function (result: TestDoneCallbackObject) { }

testDone(_testDone);

