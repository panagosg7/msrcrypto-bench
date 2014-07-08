//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// #region JSCop/JsHint

/* global self */
/* jshint -W098 */
/* W098 is 'defined but not used'. These properties are used in other scripts. */

// / <reference path="jsCopDefs.js" />


// Sets the url to for this script.
// We need this to pass to webWorkers later to instantiate them.

/// <dictionary>fprng</dictionary>

/// #endregion JSCop/JsHint



// PV 

//	/<reference path='references.ts' />



var scriptUrl = (function () {

    /* jshint -W117 */

    if (typeof document !== "undefined") {
        var scripts = document.getElementsByTagName("script");
        // Since this script is currently being evaluated
        //  it will be the last one in the list.
        return scripts[scripts.length - 1].src;
        
    } else if (typeof self !== "undefined") {
        // If this script is being run in a WebWorker, 'document' will not exist
        //  but we can use self.        
        return self.location.href;        
    }

    // Must be running in an environment without document or self.
    return null;

    /* jshint +W117 */

})();

// Indication if the user provided entropy into the entropy pool.
var fprngEntropyProvided = false;

// Support for webWorkers IE10+.
var webWorkerSupport = (typeof Worker !== "undefined");

// Is this script running in an instance of a webWorker?
var runningInWorkerInstance = (typeof importScripts !== "undefined");

// Typed Arrays support?
var typedArraySupport = (typeof Uint8Array !== "undefined");

// Property setter/getter support IE9+.
var setterSupport = (function () {
    try {
		// PV adding this cast
        Object.defineProperty({}, "oncomplete", <PropertyDescriptor>{});
        return true;
    } catch (ex) {
        return false;
    }
}());

// Run in async mode (requires web workers) and user can override to sync mode
//  by setting the .forceSync property to true on the subtle interface
//  this can be changes 'on the fly'.
var asyncMode = webWorkerSupport;

// PV commenting this out - not used in this module
//// Gets the type of a native object.
//var type = function (item) {
//    return Object.prototype.toString.call(item).replace("[object ", "").replace("]", "");
//};

var createProperty = function (parentObject, propertyName, /*@dynamic*/initialValue, getterFunction: () => any, setterFunction?: (x: any) => any) {
    /// <param name="parentObject" type="Object"/>
    /// <param name="propertyName" type="String"/>
    /// <param name="initialValue" type="Object"/>
    /// <param name="getterFunction" type="Function"/>
    /// <param name="setterFunction" type="Function" optional="true"/>

    if (!setterSupport) {
        parentObject[propertyName] = initialValue;
        return;
    }

    var setGet = {};

    //PV commented this out
    //getterFunction && (setGet.get = getterFunction);

    //setterFunction && (setGet.set = setterFunction);

    Object.defineProperty(
        parentObject,
        propertyName, <PropertyDescriptor>setGet);
};

// Collection of hash functions for global availability.
// Each hashfunction will add itself to the collection as it is evaluated.
var msrcryptoHashFunctions = {};