let hash = JSON.parse(decodeURIComponent(document.location.hash.substr(1)));

document.getElementById("msg").innerText = hash.msg;
document.getElementById("url").href = "https://" + hash.host;
document.getElementById("url").innerText = "https://" + hash.host;
