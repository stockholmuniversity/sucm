// Submit CSR view: Browse button opens the hidden file input and the chosen
// file name is shown in the read-only display field. Loaded with `defer`,
// after sucm.js.
(function () {
    "use strict";

    SucmUI.ready(function () {
        var fileInput = document.getElementById("customFile");
        var fileNameDisplay = document.getElementById("file-name-display");
        var browseButton = document.getElementById("browse-button");
        if (!fileInput || !fileNameDisplay || !browseButton) {
            return;
        }

        browseButton.addEventListener("click", function () {
            fileInput.click();
        });

        fileInput.addEventListener("change", function () {
            if (fileInput.files.length > 0) {
                fileNameDisplay.value = fileInput.files[0].name;
            }
        });
    });
})();
