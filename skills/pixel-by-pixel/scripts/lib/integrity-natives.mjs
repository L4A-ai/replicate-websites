// This function is serialized into Chromium. Keep it self-contained and install it
// before page-authored scripts run so later capture code can bypass monkeypatches.
export function integrityNativeInitScript() {
  const apply = Reflect.apply;
  const arrayConstructor = Array;
  const objectConstructor = Object;
  const regexpConstructor = RegExp;
  const jsonObject = JSON;
  const symbolConstructor = Symbol;
  const symbolIterator = Symbol.iterator;
  const arraySlice = Array.prototype.slice;
  const arrayPush = Array.prototype.push;
  const arraySort = Array.prototype.sort;
  const arrayMap = Array.prototype.map;
  const arrayFilter = Array.prototype.filter;
  const arrayFind = Array.prototype.find;
  const arrayFlatMap = Array.prototype.flatMap;
  const arraySome = Array.prototype.some;
  const arrayIncludes = Array.prototype.includes;
  const arrayJoin = Array.prototype.join;
  const arrayForEach = Array.prototype.forEach;
  const arrayIterator = Array.prototype[Symbol.iterator];
  const nodeListIterator = NodeList.prototype[Symbol.iterator];
  const htmlCollectionIterator = HTMLCollection.prototype[Symbol.iterator];
  const arrayIsArray = Array.isArray;
  const objectEntries = Object.entries;
  const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  const stringConstructor = String;
  const stringReplace = String.prototype.replace;
  const stringToLowerCase = String.prototype.toLowerCase;
  const stringSplit = String.prototype.split;
  const stringIncludes = String.prototype.includes;
  const stringStartsWith = String.prototype.startsWith;
  const stringSlice = String.prototype.slice;
  const stringTrim = String.prototype.trim;
  const stringMatchAll = String.prototype.matchAll;
  const stringPadStart = String.prototype.padStart;
  const regexpTest = RegExp.prototype.test;
  const regexpExec = RegExp.prototype.exec;
  const regexpMatchAll = RegExp.prototype[Symbol.matchAll];
  const jsonParse = JSON.parse;
  const decodeUriComponent = globalThis.decodeURIComponent;
  const mapConstructor = Map;
  const mapPrototype = Map.prototype;
  const mapGet = mapPrototype.get;
  const mapSet = mapPrototype.set;
  const mapHas = mapPrototype.has;
  const mapIterator = mapPrototype[Symbol.iterator];
  const urlConstructor = URL;
  const urlPrototype = URL.prototype;
  const urlHrefGetter = getOwnPropertyDescriptor(urlPrototype, 'href')?.get;
  const urlHashDescriptor = getOwnPropertyDescriptor(urlPrototype, 'hash');
  const urlProtocolGetter = getOwnPropertyDescriptor(urlPrototype, 'protocol')?.get;
  const urlUsernameGetter = getOwnPropertyDescriptor(urlPrototype, 'username')?.get;
  const urlPasswordGetter = getOwnPropertyDescriptor(urlPrototype, 'password')?.get;
  const urlSearchParamsGetter = getOwnPropertyDescriptor(urlPrototype, 'searchParams')?.get;
  const urlSearchParamsConstructor = URLSearchParams;
  const urlSearchParamsPrototype = URLSearchParams.prototype;
  const urlSearchParamsForEach = urlSearchParamsPrototype.forEach;
  const urlSearchParamsIterator = urlSearchParamsPrototype[Symbol.iterator];
  const documentPrototype = Document.prototype;
  const documentFragmentPrototype = DocumentFragment.prototype;
  const elementPrototype = Element.prototype;
  const nodePrototype = Node.prototype;
  const nodeBaseUriGetter = getOwnPropertyDescriptor(nodePrototype, 'baseURI')?.get;
  const formPrototype = HTMLFormElement.prototype;
  const performancePrototype = Performance.prototype;
  const shadowRootPrototype = typeof ShadowRoot === 'undefined' ? null : ShadowRoot.prototype;
  const shadowRootGetter = getOwnPropertyDescriptor(elementPrototype, 'shadowRoot')?.get;
  const elementOuterHTMLDescriptor = getOwnPropertyDescriptor(elementPrototype, 'outerHTML');
  const formActionGetter = getOwnPropertyDescriptor(formPrototype, 'action')?.get;
  const formMethodGetter = getOwnPropertyDescriptor(formPrototype, 'method')?.get;
  const formEnctypeGetter = getOwnPropertyDescriptor(formPrototype, 'enctype')?.get;
  const native = {
    documentQuerySelectorAll: documentPrototype.querySelectorAll,
    documentQuerySelector: documentPrototype.querySelector,
    documentElementsFromPoint: documentPrototype.elementsFromPoint,
    documentGetElementById: documentPrototype.getElementById,
    fragmentQuerySelectorAll: documentFragmentPrototype.querySelectorAll,
    fragmentQuerySelector: documentFragmentPrototype.querySelector,
    elementQuerySelectorAll: elementPrototype.querySelectorAll,
    elementQuerySelector: elementPrototype.querySelector,
    elementMatches: elementPrototype.matches,
    elementClosest: elementPrototype.closest,
    elementGetAttribute: elementPrototype.getAttribute,
    elementGetAttributeNS: elementPrototype.getAttributeNS,
    elementHasAttribute: elementPrototype.hasAttribute,
    elementSetAttribute: elementPrototype.setAttribute,
    elementRemoveAttribute: elementPrototype.removeAttribute,
    elementRemoveAttributeNS: elementPrototype.removeAttributeNS,
    elementOuterHTMLGetter: elementOuterHTMLDescriptor?.get,
    elementOuterHTMLSetter: elementOuterHTMLDescriptor?.set,
    elementGetBoundingClientRect: elementPrototype.getBoundingClientRect,
    nodeCloneNode: nodePrototype.cloneNode,
    nodeAppendChild: nodePrototype.appendChild,
    nodeGetRootNode: nodePrototype.getRootNode,
    shadowRootGetter,
    shadowGetElementById: shadowRootPrototype?.getElementById,
    formActionGetter,
    formMethodGetter,
    formEnctypeGetter,
    getComputedStyle: globalThis.getComputedStyle,
    performanceGetEntriesByType: performancePrototype.getEntriesByType,
    shadowElementsFromPoint: shadowRootPrototype?.elementsFromPoint
  };
  const toArray = (value) => apply(arraySlice, value || [], []);
  const queryFunction = (root, singular) => {
    if (root === document) return singular ? native.documentQuerySelector : native.documentQuerySelectorAll;
    if (root?.nodeType === 11) {
      return singular ? native.fragmentQuerySelector : native.fragmentQuerySelectorAll;
    }
    return singular ? native.elementQuerySelector : native.elementQuerySelectorAll;
  };
  const api = {
    toArray(value) {
      return toArray(value);
    },
    arrayMap(value, callback) {
      return apply(arrayMap, value, [callback]);
    },
    arrayFilter(value, callback) {
      return apply(arrayFilter, value, [callback]);
    },
    arrayFind(value, callback) {
      return apply(arrayFind, value, [callback]);
    },
    arrayFlatMap(value, callback) {
      return apply(arrayFlatMap, value, [callback]);
    },
    arraySome(value, callback) {
      return apply(arraySome, value, [callback]);
    },
    arrayIncludes(value, entry, fromIndex = 0) {
      return apply(arrayIncludes, value, [entry, fromIndex]);
    },
    arrayJoin(value, separator = ',') {
      return apply(arrayJoin, value, [separator]);
    },
    arrayForEach(value, callback) {
      return apply(arrayForEach, value, [callback]);
    },
    arrayPush(value, ...entries) {
      return apply(arrayPush, value, entries);
    },
    arraySlice(value, start, end) {
      return apply(arraySlice, value, [start, end]);
    },
    arraySort(value, callback) {
      return apply(arraySort, value, [callback]);
    },
    arrayIsArray(value) {
      return apply(arrayIsArray, arrayConstructor, [value]);
    },
    objectEntries(value) {
      return apply(objectEntries, objectConstructor, [value]);
    },
    string(value) {
      return apply(stringConstructor, undefined, [value]);
    },
    stringReplace(value, pattern, replacement) {
      return apply(stringReplace, value, [pattern, replacement]);
    },
    stringToLowerCase(value) {
      return apply(stringToLowerCase, value, []);
    },
    stringSplit(value, separator, limit) {
      return apply(stringSplit, value, limit === undefined ? [separator] : [separator, limit]);
    },
    stringIncludes(value, entry, position = 0) {
      return apply(stringIncludes, value, [entry, position]);
    },
    stringStartsWith(value, entry, position = 0) {
      return apply(stringStartsWith, value, [entry, position]);
    },
    stringSlice(value, start, end) {
      return apply(stringSlice, value, [start, end]);
    },
    stringTrim(value) {
      return apply(stringTrim, value, []);
    },
    stringMatchAll(value, pattern) {
      return apply(stringMatchAll, value, [pattern]);
    },
    stringPadStart(value, length, fill = ' ') {
      return apply(stringPadStart, value, [length, fill]);
    },
    regexpTest(pattern, value) {
      return apply(regexpTest, pattern, [value]);
    },
    regexpExec(pattern, value) {
      return apply(regexpExec, pattern, [value]);
    },
    jsonParse(value) {
      return apply(jsonParse, jsonObject, [value]);
    },
    decodeURIComponent(value) {
      return apply(decodeUriComponent, globalThis, [value]);
    },
    createMap(entries) {
      return new mapConstructor(entries);
    },
    mapGet(map, key) {
      return apply(mapGet, map, [key]);
    },
    mapSet(map, key, value) {
      return apply(mapSet, map, [key, value]);
    },
    mapHas(map, key) {
      return apply(mapHas, map, [key]);
    },
    createUrl(value, base) {
      return base === undefined ? new urlConstructor(value) : new urlConstructor(value, base);
    },
    createUrlSearchParams(value) {
      return new urlSearchParamsConstructor(value);
    },
    urlSearchParamsForEach(value, callback) {
      return apply(urlSearchParamsForEach, value, [callback]);
    },
    urlHref(url) {
      return urlHrefGetter ? apply(urlHrefGetter, url, []) : '';
    },
    urlHash(url) {
      return urlHashDescriptor?.get ? apply(urlHashDescriptor.get, url, []) : '';
    },
    setUrlHash(url, value) {
      if (urlHashDescriptor?.set) apply(urlHashDescriptor.set, url, [value]);
    },
    urlProtocol(url) {
      return urlProtocolGetter ? apply(urlProtocolGetter, url, []) : '';
    },
    urlUsername(url) {
      return urlUsernameGetter ? apply(urlUsernameGetter, url, []) : '';
    },
    urlPassword(url) {
      return urlPasswordGetter ? apply(urlPasswordGetter, url, []) : '';
    },
    urlSearchParams(url) {
      return urlSearchParamsGetter ? apply(urlSearchParamsGetter, url, []) : null;
    },
    baseUri(node) {
      return nodeBaseUriGetter ? apply(nodeBaseUriGetter, node, []) : '';
    },
    queryAll(root, selector) {
      return toArray(apply(queryFunction(root, false), root, [selector]));
    },
    queryOne(root, selector) {
      return apply(queryFunction(root, true), root, [selector]);
    },
    matches(element, selector) {
      return apply(native.elementMatches, element, [selector]);
    },
    closest(element, selector) {
      return apply(native.elementClosest, element, [selector]);
    },
    getAttribute(element, name) {
      return apply(native.elementGetAttribute, element, [name]);
    },
    getAttributeNS(element, namespace, name) {
      return apply(native.elementGetAttributeNS, element, [namespace, name]);
    },
    hasAttribute(element, name) {
      return apply(native.elementHasAttribute, element, [name]);
    },
    setAttribute(element, name, value) {
      return apply(native.elementSetAttribute, element, [name, value]);
    },
    removeAttribute(element, name) {
      return apply(native.elementRemoveAttribute, element, [name]);
    },
    removeAttributeNS(element, namespace, name) {
      return apply(native.elementRemoveAttributeNS, element, [namespace, name]);
    },
    cloneNode(node, deep = false) {
      return apply(native.nodeCloneNode, node, [deep]);
    },
    appendChild(parent, child) {
      return apply(native.nodeAppendChild, parent, [child]);
    },
    outerHTML(element) {
      return native.elementOuterHTMLGetter ? apply(native.elementOuterHTMLGetter, element, []) : '';
    },
    getRootNode(node) {
      return apply(native.nodeGetRootNode, node, []);
    },
    shadowRoot(element) {
      return native.shadowRootGetter ? apply(native.shadowRootGetter, element, []) : null;
    },
    getElementById(root, id) {
      if (root === document || !native.shadowGetElementById) {
        return apply(native.documentGetElementById, document, [id]);
      }
      return apply(native.shadowGetElementById, root, [id]);
    },
    formAction(form) {
      return native.formActionGetter ? apply(native.formActionGetter, form, []) : '';
    },
    formMethod(form) {
      return native.formMethodGetter ? apply(native.formMethodGetter, form, []) : '';
    },
    formEnctype(form) {
      return native.formEnctypeGetter ? apply(native.formEnctypeGetter, form, []) : '';
    },
    getComputedStyle(element, pseudo = null) {
      return apply(native.getComputedStyle, globalThis, [element, pseudo]);
    },
    getBoundingClientRect(element) {
      return apply(native.elementGetBoundingClientRect, element, []);
    },
    getEntriesByType(type) {
      return toArray(apply(native.performanceGetEntriesByType, performance, [type]));
    },
    elementsFromPoint(root, x, y) {
      if (root === document || !native.shadowElementsFromPoint) {
        return toArray(apply(native.documentElementsFromPoint, document, [x, y]));
      }
      return toArray(apply(native.shadowElementsFromPoint, root, [x, y]));
    },
    elementTampering(element) {
      const failures = [];
      const check = (label, read, expected) => {
        try {
          if (read() !== expected) apply(arrayPush, failures, [label]);
        } catch {
          apply(arrayPush, failures, [`${label}:unreadable`]);
        }
      };
      check('querySelectorAll', () => element.querySelectorAll, native.elementQuerySelectorAll);
      check('querySelector', () => element.querySelector, native.elementQuerySelector);
      check('matches', () => element.matches, native.elementMatches);
      check('closest', () => element.closest, native.elementClosest);
      check('getAttribute', () => element.getAttribute, native.elementGetAttribute);
      check('getAttributeNS', () => element.getAttributeNS, native.elementGetAttributeNS);
      check('hasAttribute', () => element.hasAttribute, native.elementHasAttribute);
      check('setAttribute', () => element.setAttribute, native.elementSetAttribute);
      check('removeAttribute', () => element.removeAttribute, native.elementRemoveAttribute);
      check('removeAttributeNS', () => element.removeAttributeNS, native.elementRemoveAttributeNS);
      check('cloneNode', () => element.cloneNode, native.nodeCloneNode);
      check('getBoundingClientRect', () => element.getBoundingClientRect, native.elementGetBoundingClientRect);
      check('getRootNode', () => element.getRootNode, native.nodeGetRootNode);
      try {
        if (getOwnPropertyDescriptor(element, 'shadowRoot')) apply(arrayPush, failures, ['shadowRoot:own-property']);
      } catch {
        apply(arrayPush, failures, ['shadowRoot:own-property:unreadable']);
      }
      try {
        if (getOwnPropertyDescriptor(element, 'outerHTML')) apply(arrayPush, failures, ['outerHTML:own-property']);
      } catch {
        apply(arrayPush, failures, ['outerHTML:own-property:unreadable']);
      }
      if (apply(stringToLowerCase, apply(stringConstructor, undefined, [element.tagName || '']), []) === 'form') {
        for (const name of ['action', 'method', 'enctype']) {
          try {
            if (getOwnPropertyDescriptor(element, name)) apply(arrayPush, failures, [`${name}:own-property`]);
          } catch {
            apply(arrayPush, failures, [`${name}:own-property:unreadable`]);
          }
        }
      }
      return failures;
    },
    auditElements(elements, limit = 1000) {
      const failures = api.tampering();
      for (let index = 0; index < elements.length && failures.length < limit; index += 1) {
        const entries = api.elementTampering(elements[index]);
        for (let entryIndex = 0; entryIndex < entries.length && failures.length < limit; entryIndex += 1) {
          apply(arrayPush, failures, [`element[${index}]:${entries[entryIndex]}`]);
        }
      }
      return failures;
    },
    tampering() {
      const failures = [];
      const check = (label, read, expected) => {
        try {
          if (read() !== expected) apply(arrayPush, failures, [label]);
        } catch {
          apply(arrayPush, failures, [`${label}:unreadable`]);
        }
      };
      check('Array.prototype.map', () => Array.prototype.map, arrayMap);
      check('Array.prototype.filter', () => Array.prototype.filter, arrayFilter);
      check('Array.prototype.find', () => Array.prototype.find, arrayFind);
      check('Array.prototype.flatMap', () => Array.prototype.flatMap, arrayFlatMap);
      check('Array.prototype.some', () => Array.prototype.some, arraySome);
      check('Array.prototype.includes', () => Array.prototype.includes, arrayIncludes);
      check('Array.prototype.join', () => Array.prototype.join, arrayJoin);
      check('Array.prototype.forEach', () => Array.prototype.forEach, arrayForEach);
      check('Array.prototype.push', () => Array.prototype.push, arrayPush);
      check('Array.prototype.slice', () => Array.prototype.slice, arraySlice);
      check('Array.prototype.sort', () => Array.prototype.sort, arraySort);
      check('Array.prototype.iterator', () => Array.prototype[Symbol.iterator], arrayIterator);
      check('globalThis.Array', () => globalThis.Array, arrayConstructor);
      check('Array.isArray', () => Array.isArray, arrayIsArray);
      check('globalThis.Object', () => globalThis.Object, objectConstructor);
      check('Object.entries', () => Object.entries, objectEntries);
      check('globalThis.String', () => globalThis.String, stringConstructor);
      check('String.prototype.replace', () => String.prototype.replace, stringReplace);
      check('String.prototype.toLowerCase', () => String.prototype.toLowerCase, stringToLowerCase);
      check('String.prototype.split', () => String.prototype.split, stringSplit);
      check('String.prototype.includes', () => String.prototype.includes, stringIncludes);
      check('String.prototype.startsWith', () => String.prototype.startsWith, stringStartsWith);
      check('String.prototype.slice', () => String.prototype.slice, stringSlice);
      check('String.prototype.trim', () => String.prototype.trim, stringTrim);
      check('String.prototype.matchAll', () => String.prototype.matchAll, stringMatchAll);
      check('String.prototype.padStart', () => String.prototype.padStart, stringPadStart);
      check('RegExp.prototype.test', () => RegExp.prototype.test, regexpTest);
      check('RegExp.prototype.exec', () => RegExp.prototype.exec, regexpExec);
      check('RegExp.prototype.matchAll', () => RegExp.prototype[Symbol.matchAll], regexpMatchAll);
      check('globalThis.RegExp', () => globalThis.RegExp, regexpConstructor);
      check('globalThis.JSON', () => globalThis.JSON, jsonObject);
      check('JSON.parse', () => JSON.parse, jsonParse);
      check('globalThis.Symbol', () => globalThis.Symbol, symbolConstructor);
      check('Symbol.iterator', () => Symbol.iterator, symbolIterator);
      check('globalThis.decodeURIComponent', () => globalThis.decodeURIComponent, decodeUriComponent);
      check('globalThis.Map', () => globalThis.Map, mapConstructor);
      check('Map.prototype.get', () => Map.prototype.get, mapGet);
      check('Map.prototype.set', () => Map.prototype.set, mapSet);
      check('Map.prototype.has', () => Map.prototype.has, mapHas);
      check('Map.prototype.iterator', () => Map.prototype[Symbol.iterator], mapIterator);
      check('globalThis.URL', () => globalThis.URL, urlConstructor);
      check('URL.prototype.href', () => getOwnPropertyDescriptor(URL.prototype, 'href')?.get, urlHrefGetter);
      check('URL.prototype.hash.get', () => getOwnPropertyDescriptor(URL.prototype, 'hash')?.get, urlHashDescriptor?.get);
      check('URL.prototype.hash.set', () => getOwnPropertyDescriptor(URL.prototype, 'hash')?.set, urlHashDescriptor?.set);
      check('URL.prototype.protocol', () => getOwnPropertyDescriptor(URL.prototype, 'protocol')?.get, urlProtocolGetter);
      check('URL.prototype.username', () => getOwnPropertyDescriptor(URL.prototype, 'username')?.get, urlUsernameGetter);
      check('URL.prototype.password', () => getOwnPropertyDescriptor(URL.prototype, 'password')?.get, urlPasswordGetter);
      check('URL.prototype.searchParams', () => getOwnPropertyDescriptor(URL.prototype, 'searchParams')?.get, urlSearchParamsGetter);
      check('globalThis.URLSearchParams', () => globalThis.URLSearchParams, urlSearchParamsConstructor);
      check('URLSearchParams.prototype.forEach', () => URLSearchParams.prototype.forEach, urlSearchParamsForEach);
      check('URLSearchParams.prototype.iterator', () => URLSearchParams.prototype[Symbol.iterator], urlSearchParamsIterator);
      check('NodeList.prototype.iterator', () => NodeList.prototype[Symbol.iterator], nodeListIterator);
      check('HTMLCollection.prototype.iterator', () => HTMLCollection.prototype[Symbol.iterator], htmlCollectionIterator);
      check('Document.prototype.querySelectorAll', () => documentPrototype.querySelectorAll, native.documentQuerySelectorAll);
      check('Document.prototype.querySelector', () => documentPrototype.querySelector, native.documentQuerySelector);
      check('Document.prototype.elementsFromPoint', () => documentPrototype.elementsFromPoint, native.documentElementsFromPoint);
      check('Document.prototype.getElementById', () => documentPrototype.getElementById, native.documentGetElementById);
      check('document.querySelectorAll', () => document.querySelectorAll, native.documentQuerySelectorAll);
      check('document.querySelector', () => document.querySelector, native.documentQuerySelector);
      check('DocumentFragment.prototype.querySelectorAll', () => documentFragmentPrototype.querySelectorAll, native.fragmentQuerySelectorAll);
      check('DocumentFragment.prototype.querySelector', () => documentFragmentPrototype.querySelector, native.fragmentQuerySelector);
      check('Element.prototype.querySelectorAll', () => elementPrototype.querySelectorAll, native.elementQuerySelectorAll);
      check('Element.prototype.querySelector', () => elementPrototype.querySelector, native.elementQuerySelector);
      check('Element.prototype.matches', () => elementPrototype.matches, native.elementMatches);
      check('Element.prototype.closest', () => elementPrototype.closest, native.elementClosest);
      check('Element.prototype.getAttribute', () => elementPrototype.getAttribute, native.elementGetAttribute);
      check('Element.prototype.getAttributeNS', () => elementPrototype.getAttributeNS, native.elementGetAttributeNS);
      check('Element.prototype.hasAttribute', () => elementPrototype.hasAttribute, native.elementHasAttribute);
      check('Element.prototype.setAttribute', () => elementPrototype.setAttribute, native.elementSetAttribute);
      check('Element.prototype.removeAttribute', () => elementPrototype.removeAttribute, native.elementRemoveAttribute);
      check('Element.prototype.removeAttributeNS', () => elementPrototype.removeAttributeNS, native.elementRemoveAttributeNS);
      check('Element.prototype.outerHTML.get', () => getOwnPropertyDescriptor(elementPrototype, 'outerHTML')?.get, native.elementOuterHTMLGetter);
      check('Element.prototype.outerHTML.set', () => getOwnPropertyDescriptor(elementPrototype, 'outerHTML')?.set, native.elementOuterHTMLSetter);
      check('Element.prototype.getBoundingClientRect', () => elementPrototype.getBoundingClientRect, native.elementGetBoundingClientRect);
      check('Node.prototype.cloneNode', () => nodePrototype.cloneNode, native.nodeCloneNode);
      check('Node.prototype.appendChild', () => nodePrototype.appendChild, native.nodeAppendChild);
      check('Node.prototype.getRootNode', () => nodePrototype.getRootNode, native.nodeGetRootNode);
      check('Node.prototype.baseURI', () => getOwnPropertyDescriptor(nodePrototype, 'baseURI')?.get, nodeBaseUriGetter);
      check('Element.prototype.shadowRoot', () => getOwnPropertyDescriptor(elementPrototype, 'shadowRoot')?.get, native.shadowRootGetter);
      check('HTMLFormElement.prototype.action', () => getOwnPropertyDescriptor(formPrototype, 'action')?.get, native.formActionGetter);
      check('HTMLFormElement.prototype.method', () => getOwnPropertyDescriptor(formPrototype, 'method')?.get, native.formMethodGetter);
      check('HTMLFormElement.prototype.enctype', () => getOwnPropertyDescriptor(formPrototype, 'enctype')?.get, native.formEnctypeGetter);
      check('globalThis.getComputedStyle', () => globalThis.getComputedStyle, native.getComputedStyle);
      check('Performance.prototype.getEntriesByType', () => performancePrototype.getEntriesByType, native.performanceGetEntriesByType);
      check('performance.getEntriesByType', () => performance.getEntriesByType, native.performanceGetEntriesByType);
      if (shadowRootPrototype && native.shadowElementsFromPoint) {
        check('ShadowRoot.prototype.elementsFromPoint', () => shadowRootPrototype.elementsFromPoint, native.shadowElementsFromPoint);
        check('ShadowRoot.prototype.getElementById', () => shadowRootPrototype.getElementById, native.shadowGetElementById);
      }
      return failures;
    }
  };
  Object.freeze(api);
  Object.defineProperty(globalThis, '__replicaIntegrityNatives', {
    configurable: false,
    enumerable: false,
    writable: false,
    value: api
  });
}
