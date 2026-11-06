// Certificate list (main view): search filter, column sorting and
// expandable SAN cells. Loaded with `defer`, after sucm.js.
(function () {
    "use strict";

    SucmUI.ready(function () {
        var activeSortCol = 0;
        var activeSortDir = "asc";

        function compareValues(a, b, type, direction) {
            var left = a.trim();
            var right = b.trim();

            if (type === "number") {
                left = Number(left);
                right = Number(right);
                if (Number.isNaN(left)) left = 0;
                if (Number.isNaN(right)) right = 0;
            } else if (type === "date") {
                var leftDate = Date.parse(left);
                var rightDate = Date.parse(right);
                if (!Number.isNaN(leftDate) && !Number.isNaN(rightDate)) {
                    left = leftDate;
                    right = rightDate;
                }
            }

            var result;
            if (
                type === "text" ||
                (typeof left === "string" && typeof right === "string")
            ) {
                result = String(left).localeCompare(String(right));
            } else {
                result = left < right ? -1 : left > right ? 1 : 0;
            }

            return direction === "asc" ? result : -result;
        }

        function sortTable(columnIndex, direction, type) {
            var tbody = document.querySelector("#certificates-table tbody");
            if (!tbody) {
                return;
            }
            var rows = Array.from(
                tbody.querySelectorAll("tr.certificate-row")
            );

            rows.sort(function (rowA, rowB) {
                var aText = rowA.children[columnIndex]
                    ? rowA.children[columnIndex].textContent
                    : "";
                var bText = rowB.children[columnIndex]
                    ? rowB.children[columnIndex].textContent
                    : "";
                return compareValues(aText, bText, type, direction);
            });

            rows.forEach(function (row) {
                tbody.appendChild(row);
            });
        }

        function updateSortIndicators() {
            document
                .querySelectorAll("#certificates-table thead th.sortable")
                .forEach(function (th) {
                    var baseText = th.textContent.replace(/\s+[▲▼]$/, "");
                    th.textContent = baseText;

                    if (Number(th.dataset.sortCol) === activeSortCol) {
                        th.textContent =
                            baseText + (activeSortDir === "asc" ? " ▲" : " ▼");
                    }
                });
        }

        document
            .querySelectorAll("#certificates-table thead th.sortable")
            .forEach(function (th) {
                th.addEventListener("click", function () {
                    var clickedCol = Number(th.dataset.sortCol);
                    var type = th.dataset.sortType;

                    if (activeSortCol === clickedCol) {
                        activeSortDir =
                            activeSortDir === "asc" ? "desc" : "asc";
                    } else {
                        activeSortCol = clickedCol;
                        activeSortDir = "asc";
                    }

                    sortTable(activeSortCol, activeSortDir, type);
                    updateSortIndicators();
                });
            });

        // Keep # as the default sort.
        sortTable(activeSortCol, activeSortDir, "number");
        updateSortIndicators();

        SucmUI.initSearchFilter("#certificates-table .certificate-row");
        SucmUI.initExpandableCells();
    });
})();
