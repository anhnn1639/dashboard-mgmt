/* global angular */
/*
 * Guacamole 1.6.0 observes layout with an embedded HTML <object>. The Portal
 * correctly serves X-Frame-Options: DENY, which prevents that sensor loading.
 * If the client starts at zero size, it never connects after becoming visible.
 * Observe the element itself without relaxing any framing/security headers.
 */
(function installPortalDisplayResize() {
    'use strict';

    angular.module('element').config(['$provide', function configureDisplayResize($provide) {
        $provide.decorator('guacResizeDirective', ['$delegate', '$window',
                function decorateResize(directives, $window) {
            if (typeof $window.ResizeObserver !== 'function')
                return directives;

            function linkResize(scope, element, attrs) {
                var node = element[0];
                var callback = scope.$eval(attrs.guacResize);
                var lastWidth = -1;
                var lastHeight = -1;
                var scheduled = false;
                var destroyed = false;

                function checkSize() {
                    if (destroyed || scheduled)
                        return;
                    scheduled = true;
                    scope.$evalAsync(function reportSize() {
                        scheduled = false;
                        if (destroyed)
                            return;
                        var width = node.offsetWidth;
                        var height = node.offsetHeight;
                        if (width === lastWidth && height === lastHeight)
                            return;
                        lastWidth = width;
                        lastHeight = height;
                        if (typeof callback === 'function')
                            callback(width, height);
                    });
                }

                var observer = new $window.ResizeObserver(checkSize);
                observer.observe(node);
                checkSize();
                scope.$on('$destroy', function stopObserving() {
                    destroyed = true;
                    observer.disconnect();
                });
            }

            return directives.map(function replaceSensor(directive) {
                // Angular may already have wrapped the original link function
                // in compile(), so replace both entry points.
                return angular.extend({}, directive, {
                    link: linkResize,
                    compile: function compileResize() { return linkResize; }
                });
            });
        }]);
    }]);
}());
