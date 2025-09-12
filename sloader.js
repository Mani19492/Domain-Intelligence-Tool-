(function(){
  const a = "THMx", b = "HYDPY", c = "{ctf_";
  const d = "console_pwn3d}";
  window.__showFlag = () => `${a}${b}${c}${d}`;
  console.log("Hint: Curious minds open the console...");

  // Register the Service Worker
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').then(function(reg) {
      console.log("Service Worker registered successfully.");
    }).catch(function(err) {
      console.log("Service Worker registration failed:", err);
    });
  }
})();
