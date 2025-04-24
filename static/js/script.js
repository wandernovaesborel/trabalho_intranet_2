document.addEventListener('DOMContentLoaded', function() {
    // Verificar se há mensagens flash e escondê-las após 5 segundos
    const flashMessages = document.querySelectorAll('.flash');
    if (flashMessages.length > 0) {
        flashMessages.forEach(message => {
            setTimeout(() => {
                message.style.transition = 'opacity 0.5s ease';
                message.style.opacity = '0';
                setTimeout(() => message.remove(), 500);
            }, 5000);
        });
    }
    
    // Validação de formulário de registro
    const registerForm = document.querySelector('form[action="/register"]');
    if (registerForm) {
        registerForm.addEventListener('submit', function(e) {
            const password = document.getElementById('password');
            if (password.value.length < 8) {
                e.preventDefault();
                alert('A senha deve ter pelo menos 8 caracteres.');
                password.focus();
            }
            
            const consent = document.getElementById('lgpd_consent');
            if (!consent.checked) {
                e.preventDefault();
                alert('Você deve concordar com a Política de Privacidade para se registrar.');
                consent.focus();
            }
        });
    }
    
    // Validação de formulário de login
    const loginForm = document.querySelector('form[action="/login"]');
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            const username = document.getElementById('username');
            const password = document.getElementById('password');
            
            if (!username.value || !password.value) {
                e.preventDefault();
                alert('Por favor, preencha todos os campos.');
            }
        });
    }
});