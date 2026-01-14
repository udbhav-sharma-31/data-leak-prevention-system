function showLogin() {
  document.getElementById("login-form").classList.remove("hidden");
  document.getElementById("register-form").classList.add("hidden");
  document.querySelector(".tab-indicator").style.transform = "translateX(0)";
}

function showRegister() {
  document.getElementById("register-form").classList.remove("hidden");
  document.getElementById("login-form").classList.add("hidden");
  document.querySelector(".tab-indicator").style.transform = "translateX(100%)";
}
