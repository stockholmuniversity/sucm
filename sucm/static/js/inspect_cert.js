// Inspect certificate view: submit spinners on action forms and expandable
// SAN cells. Loaded with `defer`, after sucm.js.
(function () {
    "use strict";

    SucmUI.ready(function () {
        SucmUI.initInlineFormSpinners();
        SucmUI.initExpandableCells();
    });
})();
