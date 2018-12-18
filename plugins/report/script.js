//// ToC Stuff
function fillToC() {
    $("h2,h3").each(function () {
        generateAnchor(this)
    })
}

function generateTOC() {
    $(`<nav>
          <ul id="tocContent">
          </ul>
        </nav>`).insertAfter(`h1`)
}

function generateTOCEl(text) {
    $("#tocContent").append(`<li><a href="#${text}">${text}</a></li>`)
}

function generateAnchor(titleTag) {
    let text = $(titleTag).text()
    $(titleTag).attr('id', text)
    generateTOCEl(text)
}


//// Accordion Stuff
function createAccordionElements() {
    $("h3").each(function () {
        makeAccordionActivateButton(this)
        wrapContentInPanel(this)
        setAccordionFunction(this)
    })
}

function makeAccordionActivateButton(tag) {
    let text = $(tag).text()
    $(tag).text(" ")
    $(tag).append(`<button class="accordion">${text}</button>`)
}

function wrapContentInPanel(tag) {
    let el =  $(tag).nextUntil("h3")
    $(tag).nextUntil("h2,h3").wrapAll(`<div class="panel"></div>`)

}

function setAccordionFunction(h3Tag) {
    $(h3Tag).on('click', ".accordion", function () {
        $(this).toggleClass("active")
        let panelEl = $(this).parent().next()
        let panel = panelEl[0].style
        if (panel.display === "block") panel.display = "none"
        else panel.display = "block"
    })
}


$(function () {
    generateTOC()
    fillToC()
    createAccordionElements()

})


