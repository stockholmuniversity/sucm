// Add/edit certificate form: keep the disabled notify_group <select>
// submitted via a hidden input (disabled controls are not posted), and show
// a spinner on submit. Loaded with `defer`, after sucm.js.
(function () {
    "use strict";

    SucmUI.ready(function () {
        var certTypeSelect = document.querySelector('select[name="cert_type"]');
        var notifyGroupSelect = document.querySelector(
            'select[name="notify_group"]'
        );
        if (!certTypeSelect || !notifyGroupSelect) {
            return;
        }

        var hiddenNotifyGroup = document.createElement("input");
        hiddenNotifyGroup.type = "hidden";
        hiddenNotifyGroup.id = "hiddennotify_group";
        hiddenNotifyGroup.name = "notify_group";
        notifyGroupSelect.insertAdjacentElement("afterend", hiddenNotifyGroup);

        function syncNotifyGroup() {
            if (certTypeSelect.value.trim().toLowerCase() === "automatic") {
                notifyGroupSelect.disabled = true;
                hiddenNotifyGroup.value = notifyGroupSelect.value;
            } else {
                notifyGroupSelect.disabled = false;
                hiddenNotifyGroup.value = "";
            }
        }

        syncNotifyGroup();

        certTypeSelect.addEventListener("change", syncNotifyGroup);

        notifyGroupSelect.addEventListener("change", function () {
            hiddenNotifyGroup.value = notifyGroupSelect.value;
        });

        var form = document.querySelector("form");
        var submitButton = document.getElementById("submit-button");
        var loadingSpinner = document.getElementById("loading-spinner");
        if (form) {
            form.addEventListener("submit", function () {
                if (submitButton) {
                    submitButton.disabled = true;
                }
                if (loadingSpinner) {
                    loadingSpinner.style.display = "";
                }
            });
        }
    });
})();
