// Mini IDS main.js
document.addEventListener('DOMContentLoaded', function() {
  // Auto-dismiss flash messages
  setTimeout(function() {
    document.querySelectorAll('.alert-dismissible').forEach(function(el) {
      var bsAlert = bootstrap.Alert.getOrCreateInstance(el);
      bsAlert.close();
    });
  }, 4000);
});
