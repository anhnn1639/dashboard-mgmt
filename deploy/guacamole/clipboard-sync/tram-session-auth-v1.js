/* global angular */
/*
 * Every Portal launch contains a fresh, short-lived JSON connection. Guacamole
 * otherwise sends GUAC_AUTH_TOKEN from shared localStorage along with that JSON.
 * The server can reuse the old token's connection (including its consumed relay
 * port and recording name), ignoring the newly supplied connection parameters.
 */
(function isolatePortalLaunchAuthentication() {
    'use strict';

    angular.module('storage').config(['$provide', function configureLaunchAuthentication($provide) {
        $provide.decorator('localStorageService', ['$delegate', '$window',
                function decorateLaunchStorage(storage, $window) {
            var hash = $window.location.hash || '';
            var query = hash.indexOf('?');
            if (hash.indexOf('#/client/') !== 0 || query === -1
                    || !/(?:^|&)data=[^&]/.test(hash.slice(query + 1)))
                return storage;

            // Keep this launch's auth token only in this page's memory. Do not
            // read, replace or revoke a token belonging to another remote tab.
            // Other Guacamole preferences keep their normal storage behavior.
            var token = null;
            var authKey = 'GUAC_AUTH_TOKEN';
            var getItem = storage.getItem.bind(storage);
            var setItem = storage.setItem.bind(storage);
            var removeItem = storage.removeItem.bind(storage);
            storage.getItem = function getLaunchItem(key) {
                return key === authKey ? token : getItem(key);
            };
            storage.setItem = function setLaunchItem(key, value) {
                if (key === authKey) {
                    token = value;
                    return;
                }
                return setItem(key, value);
            };
            storage.removeItem = function removeLaunchItem(key) {
                if (key === authKey) {
                    token = null;
                    return;
                }
                return removeItem(key);
            };
            return storage;
        }]);
    }]);
}());
