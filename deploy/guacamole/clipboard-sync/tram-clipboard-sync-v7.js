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
    var abortClipboardRead = null;

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
        var modifiers = {};
        var modifierKeys = [0xFFE1, 0xFFE2, 0xFFE3, 0xFFE4, 0xFFE7, 0xFFE8, 0xFFE9, 0xFFEA, 0xFFEB, 0xFFEC];
        client.__tramPasteText = function pasteText(text, stillFocused, protocol) {
            // Native paste is authoritative. An old permission prompt must not
            // hold it or overwrite its contents when answered later.
            if (abortClipboardRead)
                abortClipboardRead();
            return afterClipboardSync(function pasteIntoCurrentConnection() {
                if (!stillFocused())
                    return;
                var writer = new Guacamole.StringWriter(client.createClipboardStream('text/plain'));
                writer.sendText(text);
                writer.sendEnd();
                // SSH's terminal handles Ctrl+Shift+V (uppercase keysym V);
                // RDP and the Web console browser use Ctrl+V. Shift+Insert is
                // not a paste shortcut in Guacamole's SSH terminal.
                // Release/restore forwarded modifiers around the exact shortcut.
                var held = modifierKeys.filter(function isHeld(key) { return modifiers[key]; });
                held.forEach(function release(key) { sendKeyEvent(0, key); });
                var terminal = protocol === 'ssh' || protocol === 'telnet';
                var pasteKeysym = terminal ? 0x56 : 0x76;
                sendKeyEvent(1, 0xFFE3);
                if (terminal)
                    sendKeyEvent(1, 0xFFE1);
                sendKeyEvent(1, pasteKeysym);
                sendKeyEvent(0, pasteKeysym);
                if (terminal)
                    sendKeyEvent(0, 0xFFE1);
                sendKeyEvent(0, 0xFFE3);
                held.forEach(function restore(key) { sendKeyEvent(1, key); });
            });
        };

        client.sendKeyEvent = function sendKeyEventAfterClipboardSync() {
            var args = Array.prototype.slice.call(arguments);
            return afterClipboardSync(function forwardKeyEvent() {
                if (modifierKeys.indexOf(args[1]) !== -1)
                    modifiers[args[1]] = !!args[0];
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
        $provide.decorator('clipboardService', ['$delegate', '$window', 'ClipboardData', '$rootScope',
                function decorateClipboardService(service, $window, ClipboardData, $rootScope) {

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

                var synchronized = false;
                pendingClipboardSync = new Promise(function synchronizeClipboard(resolve) {
                    var settled = false;
                    abortClipboardRead = function cancelSupersededRead() { finish(false); };
                    // A permission prompt may never settle. It must not hold
                    // all remote keyboard/mouse input indefinitely.
                    var timeout = $window.setTimeout(function clipboardDeadline() {
                        finish(false);
                    }, 2000);

                    function finish(success) {
                        if (settled)
                            return;
                        settled = true;
                        synchronized = success;
                        $window.clearTimeout(timeout);
                        resolve();
                    }

                    try {
                        var browserClipboard = $window.navigator && $window.navigator.clipboard;
                        var update;
                        if (!browserClipboard || !browserClipboard.readText)
                            update = originalResyncClipboard();
                        else {
                            update = Promise.resolve(browserClipboard.readText())
                                .then(function clipboardRead(text) {
                                    // An older prompt resolving after the deadline
                                    // must not overwrite a newer remote clipboard.
                                    // setClipboard() writes back to the local OS
                                    // before broadcasting. That separate permission
                                    // prompt can stall inbound paste indefinitely.
                                    if (!settled)
                                        return $rootScope.$broadcast('guacClipboard', new ClipboardData({
                                            type: 'text/plain',
                                            data: text
                                        }));
                                });
                        }
                        Promise.resolve(update).then(function clipboardSent() {
                            finish(true);
                        }, function ignoreClipboardReadFailure() {
                            finish(false);
                        });
                    }
                    catch {
                        // Some browser/extension APIs throw synchronously instead
                        // of rejecting. Do not abort Angular application startup.
                        finish(false);
                    }
                })
                    .finally(function clipboardSyncComplete() {
                        if (synchronized)
                            clipboardMayHaveChanged = false;
                        pendingClipboardSync = null;
                        abortClipboardRead = null;
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
    angular.module('clipboard').run(['$document', '$window', 'guacClientManager',
            function installNativePaste($document, $window, guacClientManager) {
        var document = $document[0];
        var suppressedKeys = {};

        function focusedClient() {
            var clients = guacClientManager.getManagedClients();
            var focused = Object.keys(clients).map(function getClient(id) { return clients[id]; })
                .filter(function isFocused(item) {
                    return item.clientProperties.focused
                        && item.clientState.connectionState === 'CONNECTED'
                        && ['ssh', 'telnet', 'rdp', 'vnc'].indexOf(item.protocol) !== -1;
                });
            return focused.length === 1 ? focused[0] : null;
        }

        function isLocalEditor(target) {
            if (!target || !target.closest)
                return false;
            // Guacamole InputSink is a zero-sized textarea directly in body.
            // Let it receive native paste while leaving visible Portal fields alone.
            var sink = target.tagName === 'TEXTAREA' && target.parentElement === document.body
                && target.style.width === '0px' && target.style.height === '0px';
            return !sink && !!target.closest('input,textarea,select,[contenteditable="true"],[contenteditable=""]');
        }

        function pasteKey(event) {
            var key = String(event.key || '').toLowerCase();
            return ((event.ctrlKey || event.metaKey) && key === 'v')
                || (event.shiftKey && key === 'insert');
        }

        $window.addEventListener('keydown', function allowNativePaste(event) {
            if (!event.isTrusted || !pasteKey(event) || isLocalEditor(event.target) || !focusedClient())
                return;
            suppressedKeys[event.code || event.key] = true;
            // Keep the browser default: it generates the trusted paste event.
            // Guacamole must not cancel it or also forward V to the remote host.
            event.stopImmediatePropagation();
        }, true);
        $window.addEventListener('keyup', function finishNativePasteKey(event) {
            var key = event.code || event.key;
            if (suppressedKeys[key]) {
                delete suppressedKeys[key];
                event.stopImmediatePropagation();
            }
        }, true);
        $window.addEventListener('blur', function clearSuppressedKeys() { suppressedKeys = {}; }, true);
        $window.addEventListener('paste', function receiveNativePaste(event) {
            if (!event.isTrusted || isLocalEditor(event.target))
                return;
            var managed = focusedClient();
            if (!managed || !event.clipboardData || !managed.client.__tramPasteText)
                return;
            var types = Array.prototype.slice.call(event.clipboardData.types || []);
            if (types.indexOf('text/plain') === -1)
                return;
            var text = event.clipboardData.getData('text/plain');
            event.preventDefault();
            event.stopImmediatePropagation();
            clipboardMayHaveChanged = false;
            managed.client.__tramPasteText(text, function sameActiveConnection() {
                return focusedClient() === managed;
            }, managed.protocol);
        }, true);
    }]);
}());
