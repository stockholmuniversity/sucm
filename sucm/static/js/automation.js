// Automation view: scroll the job-log card to the bottom (most recent
// entries). Loaded with `defer`, after sucm.js.
(function () {
    "use strict";

    SucmUI.ready(function () {
        var logCard = document.getElementById("logCard");
        if (logCard) {
            logCard.scrollTop = logCard.scrollHeight;
        }
    });
})();
