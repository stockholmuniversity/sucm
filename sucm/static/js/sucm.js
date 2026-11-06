// Shared SUCM UI behaviour, no external dependencies.
// Loaded with `defer`, so the DOM is ready when this runs.
(function () {
    "use strict";

    function ready(fn) {
        if (document.readyState !== "loading") {
            fn();
        } else {
            document.addEventListener("DOMContentLoaded", fn);
        }
    }

    // Filter table rows matching the text typed into #search. Rows may be
    // limited to a CSS class (e.g. ".certificate-row") to keep the header
    // row visible while filtering.
    function initSearchFilter(rowSelector) {
        var search = document.getElementById("search");
        if (!search) {
            return;
        }
        search.addEventListener("keyup", function () {
            var value = search.value.toLowerCase();
            document.querySelectorAll(rowSelector).forEach(function (row) {
                row.style.display =
                    row.textContent.toLowerCase().indexOf(value) > -1
                        ? ""
                        : "none";
            });
        });
    }

    // Click-to-expand/collapse for .expandable-cell elements (long SAN lists).
    function initExpandableCells() {
        document.querySelectorAll(".expandable-cell").forEach(function (cell) {
            cell.addEventListener("click", function () {
                if (cell.classList.contains("expanded")) {
                    cell.classList.remove("expanded");
                    cell.style.maxHeight = "3em";
                } else {
                    cell.classList.add("expanded");
                    cell.style.maxHeight = "none";
                }
            });
        });
    }

    // Navbar hamburger toggle (replaces Bootstrap's collapse plugin, the only
    // Bootstrap JS feature the app used).
    function initNavbarToggle() {
        var toggler = document.querySelector(".navbar-toggler");
        if (!toggler) {
            return;
        }
        var target = document.querySelector(toggler.getAttribute("data-target"));
        if (!target) {
            return;
        }
        toggler.addEventListener("click", function () {
            var expanded = toggler.getAttribute("aria-expanded") === "true";
            toggler.setAttribute("aria-expanded", String(!expanded));
            target.classList.toggle("show");
        });
    }

    // Disable the submit button of any .inline-form on submit and append a
    // spinner, to prevent double submits on slow certificate operations.
    function initInlineFormSpinners() {
        document.querySelectorAll(".inline-form").forEach(function (form) {
            form.addEventListener("submit", function () {
                form.querySelectorAll('[type="submit"]').forEach(function (btn) {
                    btn.disabled = true;
                    btn.insertAdjacentHTML(
                        "afterend",
                        '<span class="spinner-border spinner-border-sm loading-spinner" role="status" aria-hidden="true"></span>'
                    );
                });
            });
        });
    }

    window.SucmUI = {
        ready: ready,
        initSearchFilter: initSearchFilter,
        initExpandableCells: initExpandableCells,
        initNavbarToggle: initNavbarToggle,
        initInlineFormSpinners: initInlineFormSpinners,
    };

    ready(initNavbarToggle);
})();
