// frontend/assets/js/auth.js

/**
 * Utility to show messages in a target element.
 * @param {string} elementId - The element ID to display the message in.
 * @param {string} message - The message to display.
 * @param {string} [type='success'] - Bootstrap alert type: 'success', 'danger', etc.
 */
export function showMessage(elementId, message, type = 'success') {
  const el = document.getElementById(elementId);
  if (el) {
    el.innerHTML = `<div class='alert alert-${type}'>${message}</div>`;
  }
}

/**
 * Register an admin or teacher.
 * @param {HTMLFormElement} form
 */
export async function registerAdmin(form) {
  const formData = new FormData(form);
  try {
    const res = await fetch('/api/admin/register', {
      method: 'POST',
      body: formData
    });
    const data = await res.json();
    if (res.ok) {
      showMessage('registerMsg', data.message, 'success');
      form.reset();
    } else {
      showMessage('registerMsg', data.message || 'Registration failed.', 'danger');
    }
  } catch (err) {
    showMessage('registerMsg', 'Network error. Please try again.', 'danger');
  }
}

/**
 * Register a student (student-only form, no role dropdown).
 * @param {HTMLFormElement} form
 */
export async function registerStudent(form) {
  const formData = new FormData(form);
  try {
    const res = await fetch('/api/admin/register', {
      method: 'POST',
      body: formData
    });
    const data = await res.json();
    if (res.ok) {
      showMessage('registerMsg', data.message, 'success');
      form.reset();
    } else {
      showMessage('registerMsg', data.message || 'Registration failed.', 'danger');
    }
  } catch (err) {
    showMessage('registerMsg', 'Network error. Please try again.', 'danger');
  }
}

/**
 * Login for any role. Handles role-based redirects.
 * @param {HTMLFormElement} form
 */
export async function loginAdmin(form) {
  const formData = {
    identifier: form.identifier.value,
    password: form.password.value
  };
  try {
    const res = await fetch('/api/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(formData)
    });
    const data = await res.json();
    if (res.ok && data.token) {
      localStorage.setItem('token', data.token);
      showMessage('loginMsg', 'Login successful! Redirecting...', 'success');
      setTimeout(() => {
        if (data.admin && data.admin.adminType === 'Super Admin') {
          window.location.href = '/profile/superadmin.html';
        } else if (data.admin && data.admin.adminType === 'ADMIN') {
          window.location.href = '/panel/admin.html';
        } else if (data.admin && data.admin.adminType === 'TEACHER') {
          window.location.href = '/panel/teacher.html';
        } else if (data.admin && data.admin.adminType === 'STUDENT') {
          window.location.href = '/panel/student.html';
        } else {
          window.location.href = '/profile/view.html';
        }
      }, 1000);
    } else {
      showMessage('loginMsg', data.message || 'Login failed.', 'danger');
    }
  } catch (err) {
    showMessage('loginMsg', 'Network error. Please try again.', 'danger');
  }
}

// For legacy inline usage
window.registerAdmin = registerAdmin;
window.registerStudent = registerStudent;
window.loginAdmin = loginAdmin;
window.showMessage = showMessage; 