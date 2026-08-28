/* global angular, Guacamole */
/*
 * Keep the browser-to-remote clipboard current when the Guacamole tab regains
 * focus. Guacamole 1.6.0 updates its internal clipboard asynchronously, while
 * keyboard and mouse input can otherwise reach the remote session first.
 */
(function installTramClipboardSync() {
    'use strict';

    var pendingClipboardSync = null;
    var clipboardMayHaveChanged = true;

    angular.module('clipboard').config(['$provide', function configureClipboardSync($provide) {
        $provide.decorator('clipboardService', ['$delegate', '$window', 'ClipboardData',
                function decorateClipboardService(service, $window, ClipboardData) {

            var originalResyncClipboard = service.resyncClipboard.bind(service);

            service.resyncClipboard = function resyncClipboard() {
                if (pendingClipboardSync)
                    return pendingClipboardSync;

                var browserClipboard = $window.navigator && $window.navigator.clipboard;
                if (!browserClipboard || !browserClipboard.readText) {
                    originalResyncClipboard();
                    clipboardMayHaveChanged = false;
                    return Promise.resolve();
                }

                var synchronized = false;
                pendingClipboardSync = Promise.resolve(browserClipboard.readText())
                    .then(function clipboardRead(text) {
                        return service.setClipboard(new ClipboardData({
                            type: 'text/plain',
                            data: text
                        }));
                    })
                    .then(function clipboardSent() {
                        synchronized = true;
                    })
                    .catch(function ignoreClipboardReadFailure() {
                        // Do not overwrite the operating-system clipboard with
                        // stale Guacamole data when browser permission is denied.
                    })
                    .finally(function clipboardSyncComplete() {
                        if (synchronized)
                            clipboardMayHaveChanged = false;
                        pendingClipboardSync = null;
                    });

                return pendingClipboardSync;
            };

            return service;
        }]);
    }]);

    angular.module('clipboard').run(['$document', '$window', 'clipboardService',
            function startClipboardSync($document, $window, clipboardService) {

        var document = $document[0];

        function markClipboardDirty() {
            clipboardMayHaveChanged = true;
        }

        function resyncIfNeeded() {
            if (!clipboardMayHaveChanged || document.visibilityState === 'hidden')
                return pendingClipboardSync;
            return clipboardService.resyncClipboard();
        }

        // Copying normally happens while another tab or application has focus.
        // Start reading the latest browser clipboard as soon as this session is
        // focused again, before its next keyboard or mouse action is forwarded.
        $window.addEventListener('blur', markClipboardDirty, true);
        $window.addEventListener('focus', resyncIfNeeded, true);
        document.addEventListener('visibilitychange', function visibilityChanged() {
            if (document.visibilityState === 'hidden')
                markClipboardDirty();
            else
                resyncIfNeeded();
        }, true);
        document.addEventListener('pointerenter', resyncIfNeeded, true);
        document.addEventListener('keydown', resyncIfNeeded, true);
        document.addEventListener('mousedown', resyncIfNeeded, true);

        function afterClipboardSync(callback) {
            var sync = pendingClipboardSync;
            if (!sync)
                return callback();
            sync.finally(callback);
        }

        // Backport the behavior of GUACAMOLE-2175 and cover keyboard paste as
        // well: input is queued in original order until clipboard sync ends.
        var clientPrototype = Guacamole.Client.prototype;
        if (!clientPrototype.__tramClipboardSyncInstalled) {
            var sendKeyEvent = clientPrototype.sendKeyEvent;
            var sendMouseState = clientPrototype.sendMouseState;

            clientPrototype.sendKeyEvent = function sendKeyEventAfterClipboardSync() {
                var args = Array.prototype.slice.call(arguments);
                var forwardKeyEvent = sendKeyEvent.bind.apply(sendKeyEvent, [this].concat(args));
                return afterClipboardSync(forwardKeyEvent);
            };

            clientPrototype.sendMouseState = function sendMouseStateAfterClipboardSync(state, force) {
                var stateSnapshot = new Guacamole.Mouse.State(
                    state.x,
                    state.y,
                    state.left,
                    state.middle,
                    state.right,
                    state.up,
                    state.down
                );
                return afterClipboardSync(sendMouseState.bind(this, stateSnapshot, force));
            };

            clientPrototype.__tramClipboardSyncInstalled = true;
        }

        resyncIfNeeded();
    }]);
}());