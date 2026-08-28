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

    function afterClipboardSync(callback) {
        var sync = pendingClipboardSync;
        if (!sync)
            return callback();
        sync.finally(function clipboardSyncSettled() {
            // An explicit paste may have queued a second read behind the
            // focus-triggered read. Do not forward input until the newest
            // synchronization in the chain has also settled.
            if (pendingClipboardSync && pendingClipboardSync !== sync)
                return afterClipboardSync(callback);
            return callback();
        });
    }

    function installClientInputGate(client) {
        if (!client || client.__tramClipboardSyncInstalled)
            return client;

        // Guacamole.Client defines these functions on each client instance,
        // not on the shared constructor prototype. Gate the real instance
        // created by ManagedClient so this also works in production SSH/RDP sessions.
        var sendKeyEvent = client.sendKeyEvent.bind(client);
        var sendMouseState = client.sendMouseState.bind(client);

        client.sendKeyEvent = function sendKeyEventAfterClipboardSync() {
            var args = Array.prototype.slice.call(arguments);
            return afterClipboardSync(function forwardKeyEvent() {
                return sendKeyEvent.apply(client, args);
            });
        };

        client.sendMouseState = function sendMouseStateAfterClipboardSync(state, force) {
            var stateSnapshot = new Guacamole.Mouse.State(
                state.x,
                state.y,
                state.left,
                state.middle,
                state.right,
                state.up,
                state.down
            );
            return afterClipboardSync(function forwardMouseState() {
                return sendMouseState(stateSnapshot, force);
            });
        };

        client.__tramClipboardSyncInstalled = true;
        return client;
    }

    angular.module('clipboard').config(['$provide', function configureClipboardSync($provide) {
        $provide.decorator('clipboardService', ['$delegate', '$window', 'ClipboardData',
                function decorateClipboardService(service, $window, ClipboardData) {

            var originalResyncClipboard = service.resyncClipboard.bind(service);

            service.resyncClipboard = function resyncClipboard(force) {
                if (pendingClipboardSync) {
                    if (!force)
                        return pendingClipboardSync;

                    // A focus-triggered read can complete with the clipboard
                    // value that Chrome cached before the tab became active.
                    // Queue one more read for an explicit paste shortcut and
                    // let input wait for that newer read as well.
                    var currentSync = pendingClipboardSync;
                    return currentSync.then(function readClipboardAgain() {
                        if (pendingClipboardSync && pendingClipboardSync !== currentSync)
                            return pendingClipboardSync;
                        return service.resyncClipboard(true);
                    });
                }

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

    angular.module('client').config(['$provide', function configureManagedClientSync($provide) {
        $provide.decorator('ManagedClient', ['$delegate', function decorateManagedClient(ManagedClient) {
            var getInstance = ManagedClient.getInstance;
            ManagedClient.getInstance = function getSynchronizedManagedClient() {
                var managedClient = getInstance.apply(this, arguments);
                installClientInputGate(managedClient.client);
                return managedClient;
            };
            return ManagedClient;
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
        function isPasteShortcut(event) {
            var key = String(event.key || '').toLowerCase();
            var code = String(event.code || '').toLowerCase();
            var keyCode = Number(event.keyCode || event.which || 0);
            var pasteWithControl = (event.ctrlKey || event.metaKey)
                && (key === 'v' || code === 'keyv' || keyCode === 86);
            var pasteWithInsert = event.shiftKey
                && (key === 'insert' || code === 'insert' || keyCode === 45);
            return pasteWithControl || pasteWithInsert;
        }

        function resyncForKeyboard(event) {
            if (isPasteShortcut(event))
                return clipboardService.resyncClipboard(true);
            return resyncIfNeeded();
        }

        document.addEventListener('keydown', resyncForKeyboard, true);
        function isMousePasteButton(event) {
            var button = Number(event.button);
            var buttons = Number(event.buttons || 0);

            // Remote terminals commonly paste on either the right button or
            // the middle button. A browser paste event is not emitted for
            // either action, so the native mouse event must trigger the read.
            return button === 1 || button === 2
                || (buttons & 4) !== 0 || (buttons & 2) !== 0;
        }

        function resyncForMouse(event) {
            if (isMousePasteButton(event))
                return clipboardService.resyncClipboard(true);
            return resyncIfNeeded();
        }

        // Capture mousedown before Guacamole converts it to remote input. The
        // sendMouseState wrapper below then holds that input until the forced
        // browser clipboard read has reached the remote clipboard.
        document.addEventListener('mousedown', resyncForMouse, true);

        resyncIfNeeded();
    }]);
}());
