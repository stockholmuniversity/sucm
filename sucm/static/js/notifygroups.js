// Notifygroups list: search filter (skips the header row by only matching
// tbody rows). Loaded with `defer`, after sucm.js.
(function () {
    "use strict";

    SucmUI.ready(function () {
        SucmUI.initSearchFilter("#myTable tbody tr");
    });
})();
