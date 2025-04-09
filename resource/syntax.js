document.addEventListener('DOMContentLoaded', function () {
  var comparisonTable = document.querySelector("#comparison");
  if (!comparisonTable) return;
  var oldStr = "";
  var newStr = "";
  comparisonTable.querySelectorAll("tr:nth-child(n+3) > td:first-child").forEach(e => { oldStr += e.innerText + "\n" })
  comparisonTable.querySelectorAll("tr:nth-child(n+3) > td:last-child").forEach(e => { newStr += e.innerText + "\n" })
  const diffString = Diff.createTwoFilesPatch('original.x86asm', 'new.x86asm', oldStr, newStr);
  const targetElement = document.createElement("div");
  comparisonTable.before(targetElement);
  var configuration = {
    drawFileList: true,
    fileListToggle: false,
    fileListStartVisible: false,
    fileContentToggle: false,
    matching: 'lines',
    outputFormat: 'side-by-side',
    synchronisedScroll: true,
    highlight: true,
    renderNothingWhenEmpty: false,
    colorScheme:"dark"
  };
  var diff2htmlUi = new Diff2HtmlUI(targetElement, diffString, configuration);
  diff2htmlUi.draw();
  diff2htmlUi.highlightCode();
  comparisonTable.style.display = "none";
});