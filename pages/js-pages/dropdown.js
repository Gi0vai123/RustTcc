function toggleDropdown() {
    document.getElementById("menuDropdown").classList.toggle("show");
}


window.addEventListener("click", function(e) {
    if (!e.target.matches(".dropdown-btn")) {
        document.getElementById("menuDropdown").classList.remove("show");
    }
});