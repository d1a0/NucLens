document.addEventListener('DOMContentLoaded', () => {
    // --- State Management ---
    const state = {
        accessToken: null,
        refreshToken: null,
        username: null,
        role: null,
        mustChangePassword: false,
        rules: [],
        users: [],
        publishedTags: [],
        // 分页状态
        rulesPagination: { page: 1, perPage: 20, total: 0, pages: 0 },
        usersPagination: { page: 1, perPage: 20, total: 0, pages: 0 },
        scansPagination: { page: 1, perPage: 20, total: 0, pages: 0 },
    };

    // --- DOM Elements ---
    const views = {
        auth: document.getElementById('auth-view'),
        changePassword: document.getElementById('change-password-view'),
        dashboard: document.getElementById('dashboard-view'),
        rules: document.getElementById('rules-view'),
        upload: document.getElementById('upload-view'),
        scans: document.getElementById('scans-view'),
        users: document.getElementById('users-view'),
        settings: document.getElementById('settings-view'),
    };

    const mainNav = document.getElementById('main-nav');
    const navUsers = document.getElementById('nav-users');
    const navSettings = document.getElementById('nav-settings');
    const usernameDisplay = document.getElementById('username-display');
    const usernameNav = document.getElementById('username-nav');

    // Auth forms
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    const showRegisterLink = document.getElementById('show-register');
    const showLoginLink = document.getElementById('show-login');

    // Buttons
    const loginBtn = document.getElementById('login-btn');
    const registerBtn = document.getElementById('register-btn');
    const logoutBtn = document.getElementById('logout-btn');
    const changePasswordBtn = document.getElementById('change-password-btn');
    const filterRulesBtn = document.getElementById('filter-rules-btn');
    const clearFilterBtn = document.getElementById('clear-filter-btn');
    const gotoUploadBtn = document.getElementById('goto-upload-btn');
    const uploadRuleBtn = document.getElementById('upload-rule-btn');
    const selectFileBtn = document.getElementById('select-file-btn');
    const submitYamlTextBtn = document.getElementById('submit-yaml-text-btn');
    const submitScanBtn = document.getElementById('submit-scan-btn');
    const addUserBtn = document.getElementById('add-user-btn');
    const filterUsersBtn = document.getElementById('filter-users-btn');
    const confirmAddUserBtn = document.getElementById('confirm-add-user-btn');

    // Inputs
    const loginUsernameInput = document.getElementById('login-username');
    const loginPasswordInput = document.getElementById('login-password');
    const registerUsernameInput = document.getElementById('register-username');
    const registerPasswordInput = document.getElementById('register-password');
    const registerRoleInput = document.getElementById('register-role');
    const oldPasswordInput = document.getElementById('old-password');
    const newPasswordInput = document.getElementById('new-password');
    const confirmPasswordInput = document.getElementById('confirm-password');
    const yamlUploadInput = document.getElementById('yaml-upload-input');
    const yamlTextInput = document.getElementById('yaml-text-input');
    const filterTagsInput = document.getElementById('filter-tags-input');
    const scanTargetUrlInput = document.getElementById('scan-target-url');
    const scanTagsInput = document.getElementById('scan-tags-input');
    const selectedFileNameDisplay = document.getElementById('selected-file-name');
    const filterUserStatus = document.getElementById('filter-user-status');

    // Containers
    const rulesTableBody = document.querySelector('#rules-table tbody');
    const scansTableBody = document.querySelector('#scans-table tbody');
    const usersTableBody = document.querySelector('#users-table tbody');
    const selectedScanTagsContainer = document.getElementById('selected-scan-tags');
    const availableTagsList = document.getElementById('available-tags-list');
    const dropZone = document.getElementById('drop-zone');

    // Modal
    const modal = document.getElementById('modal');
    const modalTitle = document.getElementById('modal-title');
    const modalBody = document.getElementById('modal-body');
    const addUserModal = document.getElementById('add-user-modal');

    // Stats
    const statRules = document.getElementById('stat-rules');
    const statPublished = document.getElementById('stat-published');
    const statScans = document.getElementById('stat-scans');
    const statPendingUsers = document.getElementById('stat-pending-users');
    const statPendingUsersCard = document.getElementById('stat-pending-users-card');

    // Form messages
    const loginMessage = document.getElementById('login-message');
    const registerMessage = document.getElementById('register-message');
    const changePasswordMessage = document.getElementById('change-password-message');

    // --- Toast Notification Helper ---
    const toastEl = document.getElementById('toast-notification');
    let toastTimer = null;
    
    function showToast(message, type = 'success', duration = 2000) {
        if (!toastEl) return;
        
        // 清除之前的定时器
        if (toastTimer) {
            clearTimeout(toastTimer);
            toastEl.classList.remove('show');
        }
        
        toastEl.textContent = message;
        toastEl.className = `toast-notification ${type}`;
        
        // 显示
        requestAnimationFrame(() => {
            toastEl.classList.add('show');
        });
        
        // 自动隐藏
        toastTimer = setTimeout(() => {
            toastEl.classList.remove('show');
        }, duration);
    }

    // --- Form Message Helper ---
    function showFormMessage(element, message, type = 'error') {
        if (!element) return;
        element.textContent = message;
        element.className = `form-message ${type}`;
    }

    function clearFormMessage(element) {
        if (!element) return;
        element.textContent = '';
        element.className = 'form-message';
    }

    // --- API Helper ---
    const api = {
        async request(endpoint, options = {}) {
            const headers = { 'Content-Type': 'application/json', ...options.headers };
            if (state.accessToken) {
                headers['Authorization'] = `Bearer ${state.accessToken}`;
            }

            const response = await fetch(`/api${endpoint}`, { ...options, headers });

            if (response.status === 401) {
                const refreshed = await this.refreshToken();
                if (refreshed) {
                    headers['Authorization'] = `Bearer ${state.accessToken}`;
                    const retryResponse = await fetch(`/api${endpoint}`, { ...options, headers });
                    return this.handleResponse(retryResponse);
                } else {
                    handleLogout();
                    return Promise.reject('Session expired');
                }
            }
            return this.handleResponse(response);
        },

        async handleResponse(response, skipAlert = false) {
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ msg: '发生未知错误' }));
                const authErrors = ['User not found', 'Token has expired', 'Invalid token', 'Signature verification failed', 'Signature has expired'];
                if (authErrors.some(err => errorData.msg && errorData.msg.includes(err))) {
                    handleLogout();
                    return Promise.reject(errorData);
                }
                if (!skipAlert) alert(`错误: ${errorData.msg}`);
                return Promise.reject(errorData);
            }
            if (response.status === 204 || response.headers.get('Content-Length') === '0') {
                return null;
            }
            return response.json();
        },

        async refreshToken() {
            try {
                const response = await fetch('/api/refresh', {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${state.refreshToken}` },
                });
                if (!response.ok) return false;
                const data = await response.json();
                state.accessToken = data.access_token;
                localStorage.setItem('accessToken', state.accessToken);
                return true;
            } catch (error) {
                return false;
            }
        },

        // Auth requests without alert (for login/register/change-password)
        async requestAuth(endpoint, options = {}) {
            const headers = { 'Content-Type': 'application/json', ...options.headers };
            if (state.accessToken) {
                headers['Authorization'] = `Bearer ${state.accessToken}`;
            }
            const response = await fetch(`/api${endpoint}`, { ...options, headers });
            return this.handleResponse(response, true);
        },

        login: (username, password) => api.requestAuth('/login', {
            method: 'POST',
            body: JSON.stringify({ username, password }),
        }),
        register: (username, password, role) => api.requestAuth('/register', {
            method: 'POST',
            body: JSON.stringify({ username, password, role }),
        }),
        changePassword: (old_password, new_password) => api.requestAuth('/change-password', {
            method: 'POST',
            body: JSON.stringify({ old_password, new_password }),
        }),
        getRules: (tags = '', page = 1, perPage = 20, status = '', search = '') => api.request(`/yaml?tags=${tags}&page=${page}&per_page=${perPage}&status=${status}&search=${encodeURIComponent(search)}`),
        getRuleContent: (ruleId) => api.request(`/yaml/${ruleId}/content`),
        uploadRule: (formData) => fetch('/api/yaml/upload', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${state.accessToken}` },
            body: formData,
        }),
        uploadRuleText: (yamlContent) => api.request('/yaml/upload-text', {
            method: 'POST',
            body: JSON.stringify({ content: yamlContent }),
        }),
        deleteRule: (ruleId) => api.request(`/yaml/${ruleId}`, { method: 'DELETE' }),
        updateRule: (ruleId, data) => api.request(`/yaml/${ruleId}`, { method: 'PUT', body: JSON.stringify(data) }),
        validateRule: (ruleId) => api.request(`/yaml/${ruleId}/validate`, { method: 'POST' }),
        publishRule: (ruleId) => api.request(`/yaml/${ruleId}/publish`, { method: 'POST' }),
        unpublishRule: (ruleId) => api.request(`/yaml/${ruleId}/unpublish`, { method: 'POST' }),
        getPublishedTags: (all = false) => api.request(`/tags?all=${all}`),
        getScans: (page = 1, perPage = 20) => api.request(`/scan/history?page=${page}&per_page=${perPage}`),
        submitScan: (target_url, tags) => api.request('/scan', {
            method: 'POST',
            body: JSON.stringify({ target_url, tags }),
        }),
        getScanSummary: (taskId) => api.request(`/scan/${taskId}/summary`),
        // User management
        getUsers: (page = 1, perPage = 20, status = '', search = '') => api.request(`/admin/users?page=${page}&per_page=${perPage}&status=${status}&search=${encodeURIComponent(search)}`),
        approveUser: (userId) => api.request(`/admin/users/${userId}/approve`, { method: 'POST' }),
        rejectUser: (userId) => api.request(`/admin/users/${userId}/reject`, { method: 'POST' }),
        deleteUser: (userId) => api.request(`/admin/users/${userId}`, { method: 'DELETE' }),
        updateUserRole: (userId, role) => api.request(`/admin/users/${userId}/role`, { method: 'PUT', body: JSON.stringify({ role }) }),
        resetUserPassword: (userId, password) => api.request(`/admin/users/${userId}/password`, { method: 'PUT', body: JSON.stringify({ password }) }),
        createUser: (username, password, role) => api.request('/admin/users', {
            method: 'POST',
            body: JSON.stringify({ username, password, role }),
        }),
        // 批量操作
        importRules: async (formData) => {
            const response = await fetch('/api/yaml/import', {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${state.accessToken}` },
                body: formData,
            });
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.msg || '导入失败');
            }
            return response.json();
        },
        exportRules: async () => {
            const response = await fetch(`/api/yaml/export`, {
                method: 'GET',
                headers: { 'Authorization': `Bearer ${state.accessToken}` },
            });
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.msg || '导出失败');
            }
            return response.blob();
        },
        batchValidate: (ruleIds) => api.request('/yaml/batch/validate', {
            method: 'POST',
            body: JSON.stringify({ rule_ids: ruleIds }),
        }),
        batchPublish: (ruleIds) => api.request('/yaml/batch/publish', {
            method: 'POST',
            body: JSON.stringify({ rule_ids: ruleIds }),
        }),
        batchDelete: (ruleIds) => api.request('/yaml/batch/delete', {
            method: 'POST',
            body: JSON.stringify({ rule_ids: ruleIds }),
        }),
    };

    // --- View Management ---
    function showView(viewId) {
        Object.values(views).forEach(view => {
            if (view) view.style.display = 'none';
        });
        if (views[viewId]) {
            views[viewId].style.display = 'block';
        }
        updateNav(viewId);
    }

    function updateNav(activeView) {
        document.querySelectorAll('.nav-links a').forEach(a => {
            if (a.id === `nav-${activeView}`) {
                a.classList.add('active');
            } else {
                a.classList.remove('active');
            }
        });
    }

    // --- Authentication Handlers ---
    function handleLoginSuccess(data, username) {
        state.accessToken = data.access_token;
        state.refreshToken = data.refresh_token;
        state.username = username;
        state.role = data.role || 'user';
        state.mustChangePassword = data.must_change_password || false;

        localStorage.setItem('accessToken', state.accessToken);
        localStorage.setItem('refreshToken', state.refreshToken);
        localStorage.setItem('username', state.username);
        localStorage.setItem('role', state.role);

        // 检查是否需要修改密码
        if (state.mustChangePassword) {
            mainNav.style.display = 'none';
            showView('changePassword');
            return;
        }

        usernameDisplay.textContent = username;
        if (usernameNav) usernameNav.textContent = username;
        mainNav.style.display = 'flex';
        
        // 显示/隐藏用户管理和系统设置入口（仅管理员可见）
        if (state.role === 'admin') {
            navUsers.style.display = 'inline';
            if (navSettings) navSettings.style.display = 'inline';
        } else {
            navUsers.style.display = 'none';
            if (navSettings) navSettings.style.display = 'none';
        }
        
        showView('dashboard');
        loadDashboardStats();
        window.location.hash = 'dashboard';
    }

    function handleLogout() {
        state.accessToken = null;
        state.refreshToken = null;
        state.username = null;
        state.role = null;
        state.mustChangePassword = false;

        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
        localStorage.removeItem('username');
        localStorage.removeItem('role');

        mainNav.style.display = 'none';
        showView('auth');
        loginUsernameInput.value = '';
        loginPasswordInput.value = '';
        window.location.hash = '';
    }

    function navigateToHash(hash) {
        if (!hash || hash === '' || hash === 'auth') {
            showView('dashboard');
            loadDashboardStats();
            return;
        }
        const validViews = ['dashboard', 'rules', 'upload', 'scans', 'users', 'settings'];
        if (validViews.includes(hash)) {
            // 用户管理和系统设置只有管理员能访问
            if ((hash === 'users' || hash === 'settings') && state.role !== 'admin') {
                showView('dashboard');
                return;
            }
            showView(hash);
            if (hash === 'dashboard') loadDashboardStats();
            if (hash === 'rules') {
                loadRules();
                updateBatchToolbar();
                updateRulesTableHeader();
            }
            if (hash === 'scans') {
                loadPublishedTags();
                loadScans();
            }
            if (hash === 'users') loadUsers();
            if (hash === 'settings') loadSettings();
            if (hash === 'upload') {
                yamlUploadInput.value = '';
                yamlTextInput.value = '';
                selectedFileNameDisplay.textContent = '';
                uploadRuleBtn.disabled = true;
            }
        } else {
            showView('dashboard');
            loadDashboardStats();
        }
    }
    
    // 更新规则表头（显示/隐藏复选框列）
    function updateRulesTableHeader() {
        const userRole = state.role || 'user';
        const checkboxHeader = document.querySelector('#rules-table .checkbox-header');
        const selectAllCheckbox = document.getElementById('select-all-rules');
        
        if (userRole === 'user') {
            if (checkboxHeader) checkboxHeader.style.display = 'none';
        } else {
            if (checkboxHeader) checkboxHeader.style.display = '';
            // 绑定全选事件
            if (selectAllCheckbox && !selectAllCheckbox._boundEvent) {
                selectAllCheckbox.addEventListener('change', () => {
                    toggleSelectAll(selectAllCheckbox.checked);
                });
                selectAllCheckbox._boundEvent = true;
            }
        }
        
        // 更新导入导出按钮可见性
        if (importRulesBtn) {
            importRulesBtn.style.display = userRole === 'admin' ? '' : 'none';
        }
        if (exportRulesBtn) {
            exportRulesBtn.style.display = (userRole === 'admin' || userRole === 'editor') ? '' : 'none';
        }
    }

    function init() {
        const savedAccessToken = localStorage.getItem('accessToken');
        const savedRefreshToken = localStorage.getItem('refreshToken');
        const savedUsername = localStorage.getItem('username');
        const savedRole = localStorage.getItem('role');

        if (savedAccessToken && savedRefreshToken && savedUsername) {
            state.accessToken = savedAccessToken;
            state.refreshToken = savedRefreshToken;
            state.username = savedUsername;
            state.role = savedRole || 'user';

            usernameDisplay.textContent = savedUsername;
            if (usernameNav) usernameNav.textContent = savedUsername;
            mainNav.style.display = 'flex';
            
            if (state.role === 'admin') {
                navUsers.style.display = 'inline';
                if (navSettings) navSettings.style.display = 'inline';
            } else {
                navUsers.style.display = 'none';
                if (navSettings) navSettings.style.display = 'none';
            }

            const hash = window.location.hash.slice(1) || 'dashboard';
            navigateToHash(hash);
        } else {
            mainNav.style.display = 'none';
            showView('auth');
        }

        window.addEventListener('hashchange', () => {
            if (state.accessToken && !state.mustChangePassword) {
                const hash = window.location.hash.slice(1);
                navigateToHash(hash);
            }
        });

        // 加载版本信息
        loadVersionInfo();
    }

    // --- 加载版本信息 ---
    async function loadVersionInfo() {
        try {
            const response = await fetch('/api/version');
            if (response.ok) {
                const data = await response.json();
                const versionEl = document.getElementById('version-info');
                if (versionEl) {
                    versionEl.textContent = `${data.name} v${data.version}`;
                }
            }
        } catch (error) {
            console.log('获取版本信息失败');
        }
    }

    // --- Event Handlers: Auth ---
    showRegisterLink.addEventListener('click', (e) => {
        e.preventDefault();
        clearFormMessage(loginMessage);
        clearFormMessage(registerMessage);
        loginForm.style.display = 'none';
        registerForm.style.display = 'block';
    });

    showLoginLink.addEventListener('click', (e) => {
        e.preventDefault();
        clearFormMessage(loginMessage);
        clearFormMessage(registerMessage);
        registerForm.style.display = 'none';
        loginForm.style.display = 'block';
    });

    loginBtn.addEventListener('click', async () => {
        clearFormMessage(loginMessage);
        const username = loginUsernameInput.value.trim();
        const password = loginPasswordInput.value;
        if (!username || !password) {
            showFormMessage(loginMessage, '请输入用户名和密码');
            return;
        }
        try {
            const data = await api.login(username, password);
            clearFormMessage(loginMessage);
            handleLoginSuccess(data, username);
        } catch (error) {
            console.error('登录错误:', error);
            showFormMessage(loginMessage, error.msg || '登录失败，请检查用户名和密码');
        }
    });

    // 支持回车键登录
    loginPasswordInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') loginBtn.click();
    });
    loginUsernameInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') loginPasswordInput.focus();
    });

    registerBtn.addEventListener('click', async () => {
        clearFormMessage(registerMessage);
        const username = registerUsernameInput.value.trim();
        const password = registerPasswordInput.value;
        const role = registerRoleInput.value;
        if (!username || !password) {
            showFormMessage(registerMessage, '请输入用户名和密码');
            return;
        }
        if (password.length < 6) {
            showFormMessage(registerMessage, '密码长度至少6位');
            return;
        }
        try {
            await api.register(username, password, role);
            showFormMessage(registerMessage, '注册申请已提交，请等待管理员审核', 'success');
            registerUsernameInput.value = '';
            registerPasswordInput.value = '';
            // 3秒后自动跳转到登录
            setTimeout(() => {
                showLoginLink.click();
            }, 2000);
        } catch (error) {
            console.error('注册错误:', error);
            showFormMessage(registerMessage, error.msg || '注册失败，请稍后重试');
        }
    });

    logoutBtn.addEventListener('click', (e) => {
        e.preventDefault();
        handleLogout();
    });

    changePasswordBtn.addEventListener('click', async () => {
        clearFormMessage(changePasswordMessage);
        const oldPwd = oldPasswordInput.value;
        const newPwd = newPasswordInput.value;
        const confirmPwd = confirmPasswordInput.value;

        if (!oldPwd || !newPwd || !confirmPwd) {
            showFormMessage(changePasswordMessage, '请填写所有密码字段');
            return;
        }
        if (newPwd.length < 6) {
            showFormMessage(changePasswordMessage, '新密码长度至少6位');
            return;
        }
        if (newPwd !== confirmPwd) {
            showFormMessage(changePasswordMessage, '两次输入的新密码不一致');
            return;
        }
        try {
            await api.changePassword(oldPwd, newPwd);
            showFormMessage(changePasswordMessage, '密码修改成功！', 'success');
            state.mustChangePassword = false;
            oldPasswordInput.value = '';
            newPasswordInput.value = '';
            confirmPasswordInput.value = '';
            
            // 1秒后跳转到仪表盘
            setTimeout(() => {
                clearFormMessage(changePasswordMessage);
                usernameDisplay.textContent = state.username;
                mainNav.style.display = 'flex';
                if (state.role === 'admin') {
                    navUsers.style.display = 'inline';
                }
                showView('dashboard');
                loadDashboardStats();
                window.location.hash = 'dashboard';
            }, 1000);
        } catch (error) {
            console.error('修改密码错误:', error);
            showFormMessage(changePasswordMessage, error.msg || '密码修改失败');
        }
    });

    // --- Event Handlers: Navigation ---
    document.getElementById('nav-dashboard').addEventListener('click', (e) => {
        e.preventDefault();
        window.location.hash = 'dashboard';
    });
    document.getElementById('nav-rules').addEventListener('click', (e) => {
        e.preventDefault();
        window.location.hash = 'rules';
    });
    document.getElementById('nav-upload').addEventListener('click', (e) => {
        e.preventDefault();
        window.location.hash = 'upload';
    });
    document.getElementById('nav-scans').addEventListener('click', (e) => {
        e.preventDefault();
        window.location.hash = 'scans';
    });
    navUsers.addEventListener('click', (e) => {
        e.preventDefault();
        window.location.hash = 'users';
    });

    gotoUploadBtn.addEventListener('click', () => {
        window.location.hash = 'upload';
    });

    // --- Event Handlers: Rules ---
    filterRulesBtn.addEventListener('click', () => loadRules(1));
    clearFilterBtn.addEventListener('click', () => {
        filterTagsInput.value = '';
        const statusSelect = document.getElementById('filter-status-select');
        if (statusSelect) statusSelect.value = '';
        loadRules(1);
    });

    // 状态筛选下拉框
    const filterStatusSelect = document.getElementById('filter-status-select');
    filterStatusSelect?.addEventListener('change', () => loadRules(1));

    // --- Event Handlers: Batch Operations ---
    const importRulesBtn = document.getElementById('import-rules-btn');
    const exportRulesBtn = document.getElementById('export-rules-btn');
    const batchValidateBtn = document.getElementById('batch-validate-btn');
    const batchPublishBtn = document.getElementById('batch-publish-btn');
    const batchDeleteBtn = document.getElementById('batch-delete-btn');
    const importZipInput = document.getElementById('import-zip-input');
    const batchToolbar = document.querySelector('.batch-toolbar');
    const selectedCountSpan = document.getElementById('selected-count');
    
    // 选中的规则ID集合
    let selectedRuleIds = new Set();

    // 更新批量工具栏按钮状态
    function updateBatchToolbar() {
        const userRole = state.role || 'user';
        
        // 根据角色显示/隐藏按钮
        if (batchToolbar) {
            if (userRole === 'user') {
                batchToolbar.style.display = 'none';
            } else {
                batchToolbar.style.display = 'flex';
                
                // 只有管理员可以导入
                if (importRulesBtn) {
                    importRulesBtn.style.display = userRole === 'admin' ? '' : 'none';
                }
                
                // 批量验证：admin/editor可用
                if (batchValidateBtn) {
                    batchValidateBtn.disabled = selectedRuleIds.size === 0;
                }
                
                // 批量发布：只有admin可用
                if (batchPublishBtn) {
                    batchPublishBtn.style.display = userRole === 'admin' ? '' : 'none';
                    batchPublishBtn.disabled = selectedRuleIds.size === 0;
                }
                
                // 批量删除：只有admin可用
                if (batchDeleteBtn) {
                    batchDeleteBtn.style.display = userRole === 'admin' ? '' : 'none';
                    batchDeleteBtn.disabled = selectedRuleIds.size === 0;
                }
            }
        }
        
        // 更新选中计数
        if (selectedCountSpan) {
            selectedCountSpan.innerHTML = `已选择 <strong>${selectedRuleIds.size}</strong> 项`;
        }
    }

    // 导出规则
    exportRulesBtn?.addEventListener('click', async () => {
        try {
            exportRulesBtn.disabled = true;
            exportRulesBtn.textContent = '导出中...';
            
            const blob = await api.exportRules();
            
            // 创建下载链接
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `rules_export_${new Date().toISOString().slice(0,10)}.zip`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            
        } catch (error) {
            console.error('导出错误:', error);
            showToast('导出失败: ' + (error.message || '未知错误'), 'error');
        } finally {
            exportRulesBtn.disabled = false;
            exportRulesBtn.textContent = '导出规则';
        }
    });

    // 导入规则
    importRulesBtn?.addEventListener('click', () => {
        importZipInput.click();
    });

    importZipInput?.addEventListener('change', async () => {
        const file = importZipInput.files[0];
        if (!file) return;
        
        if (!file.name.endsWith('.zip')) {
            showToast('请选择 ZIP 文件', 'warning');
            importZipInput.value = '';
            return;
        }

        try {
            importRulesBtn.disabled = true;
            importRulesBtn.textContent = '导入中...';
            
            const formData = new FormData();
            formData.append('file', file);
            
            const result = await api.importRules(formData);
            
            // 显示导入结果
            const successCount = result.imported ? result.imported.length : 0;
            const skipCount = result.skipped ? result.skipped.length : 0;
            const errorCount = result.errors ? result.errors.length : 0;
            
            let message = `导入完成！\n成功: ${successCount} 个\n跳过: ${skipCount} 个\n失败: ${errorCount} 个`;
            
            if (result.errors && result.errors.length > 0) {
                message += '\n\n失败详情:\n';
                result.errors.slice(0, 5).forEach(err => {
                    message += `- ${err}\n`;
                });
                if (result.errors.length > 5) {
                    message += `... 还有 ${result.errors.length - 5} 个失败`;
                }
            }
            
            // 简化消息
            const toastMsg = `导入完成！成功 ${successCount} 个${skipCount > 0 ? '，跳过 ' + skipCount + ' 个' : ''}${errorCount > 0 ? '，失败 ' + errorCount + ' 个' : ''}`;
            showToast(toastMsg, errorCount > 0 ? 'warning' : 'success', 3000);
            
            // 刷新规则列表
            loadRules();
        } catch (error) {
            console.error('导入错误:', error);
            showToast('导入失败: ' + (error.message || '未知错误'), 'error');
        } finally {
            importRulesBtn.disabled = false;
            importRulesBtn.textContent = '导入规则';
            importZipInput.value = '';
        }
    });

    // 批量验证（分批处理，每批10条）
    batchValidateBtn?.addEventListener('click', async () => {
        if (selectedRuleIds.size === 0) {
            showToast('请先选择要验证的规则', 'warning');
            return;
        }
        
        const ids = Array.from(selectedRuleIds);
        const batchSize = 10; // 每批10条
        const totalBatches = Math.ceil(ids.length / batchSize);
        let totalSuccess = 0;
        let totalFailed = 0;
        let allFailed = [];
        
        try {
            batchValidateBtn.disabled = true;
            
            for (let i = 0; i < totalBatches; i++) {
                const start = i * batchSize;
                const end = Math.min(start + batchSize, ids.length);
                const batchIds = ids.slice(start, end);
                
                // 更新按钮显示进度
                batchValidateBtn.textContent = `验证中 (${end}/${ids.length})...`;
                
                try {
                    const result = await api.batchValidate(batchIds);
                    totalSuccess += result.success ? result.success.length : 0;
                    if (result.failed && result.failed.length > 0) {
                        totalFailed += result.failed.length;
                        allFailed = allFailed.concat(result.failed);
                    }
                    
                    // 每批完成后刷新规则列表，实时更新状态
                    await loadRules();
                } catch (error) {
                    console.error(`批次 ${i + 1} 验证失败:`, error);
                    totalFailed += batchIds.length;
                }
                
                // 每批次间隔100ms，避免服务器压力过大
                if (i < totalBatches - 1) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                }
            }
            
            showToast(`批量验证完成！成功 ${totalSuccess} 个${totalFailed > 0 ? '，失败 ' + totalFailed + ' 个' : ''}`, 
                totalFailed > 0 ? 'warning' : 'success', 3000);
            
            // 清空选择并刷新
            selectedRuleIds.clear();
            updateBatchToolbar();
            loadRules();
        } catch (error) {
            console.error('批量验证错误:', error);
            showToast('批量验证失败: ' + (error.message || '未知错误'), 'error');
        } finally {
            batchValidateBtn.disabled = false;
            batchValidateBtn.textContent = '批量验证';
        }
    });

    // 批量发布
    batchPublishBtn?.addEventListener('click', async () => {
        if (selectedRuleIds.size === 0) {
            showToast('请先选择要发布的规则', 'warning');
            return;
        }
        
        const ids = Array.from(selectedRuleIds);
        
        try {
            batchPublishBtn.disabled = true;
            batchPublishBtn.textContent = '发布中...';
            
            const result = await api.batchPublish(ids);
            
            const successCount = result.success ? result.success.length : 0;
            const failCount = result.failed ? result.failed.length : 0;
            
            showToast(`批量发布完成！成功 ${successCount} 个${failCount > 0 ? '，失败 ' + failCount + ' 个' : ''}`, 
                failCount > 0 ? 'warning' : 'success', 3000);
            
            // 清空选择并刷新
            selectedRuleIds.clear();
            updateBatchToolbar();
            loadRules();
        } catch (error) {
            console.error('批量发布错误:', error);
            showToast('批量发布失败: ' + (error.message || '未知错误'), 'error');
        } finally {
            batchPublishBtn.disabled = false;
            batchPublishBtn.textContent = '批量发布';
        }
    });

    // 批量删除
    batchDeleteBtn?.addEventListener('click', async () => {
        if (selectedRuleIds.size === 0) {
            showToast('请先选择要删除的规则', 'warning');
            return;
        }
        
        if (!confirm(`确定要删除选中的 ${selectedRuleIds.size} 个规则吗？此操作不可恢复！`)) {
            return;
        }
        
        const ids = Array.from(selectedRuleIds);
        
        try {
            batchDeleteBtn.disabled = true;
            batchDeleteBtn.textContent = '删除中...';
            
            const result = await api.batchDelete(ids);
            
            const successCount = result.success ? result.success.length : 0;
            const failCount = result.failed ? result.failed.length : 0;
            
            showToast(`批量删除完成！成功 ${successCount} 个${failCount > 0 ? '，失败 ' + failCount + ' 个' : ''}`, 
                failCount > 0 ? 'warning' : 'success', 3000);
            
            // 清空选择并刷新
            selectedRuleIds.clear();
            updateBatchToolbar();
            loadRules();
        } catch (error) {
            console.error('批量删除错误:', error);
            showToast('批量删除失败: ' + (error.message || '未知错误'), 'error');
        } finally {
            batchDeleteBtn.disabled = false;
            batchDeleteBtn.textContent = '批量删除';
        }
    });

    // 全选/取消全选
    function toggleSelectAll(checked) {
        const checkboxes = document.querySelectorAll('.rule-checkbox');
        checkboxes.forEach(cb => {
            cb.checked = checked;
            const ruleId = parseInt(cb.dataset.ruleId);
            if (checked) {
                selectedRuleIds.add(ruleId);
            } else {
                selectedRuleIds.delete(ruleId);
            }
        });
        updateBatchToolbar();
    }

    // 单个规则选择变化
    function handleRuleCheckboxChange(ruleId, checked) {
        if (checked) {
            selectedRuleIds.add(ruleId);
        } else {
            selectedRuleIds.delete(ruleId);
        }
        
        // 更新全选框状态
        const selectAllCheckbox = document.getElementById('select-all-rules');
        const checkboxes = document.querySelectorAll('.rule-checkbox');
        if (selectAllCheckbox) {
            selectAllCheckbox.checked = selectedRuleIds.size === checkboxes.length && checkboxes.length > 0;
        }
        
        updateBatchToolbar();
    }

    // --- Event Handlers: Upload ---
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => {
                c.classList.remove('active');
                c.style.display = 'none';
            });
            btn.classList.add('active');
            const tabId = `tab-${btn.dataset.tab}`;
            const tabContent = document.getElementById(tabId);
            tabContent.classList.add('active');
            tabContent.style.display = 'block';
        });
    });

    selectFileBtn.addEventListener('click', () => yamlUploadInput.click());

    yamlUploadInput.addEventListener('change', () => {
        const file = yamlUploadInput.files[0];
        if (file) {
            selectedFileNameDisplay.textContent = `已选择: ${file.name}`;
            uploadRuleBtn.disabled = false;
        } else {
            selectedFileNameDisplay.textContent = '';
            uploadRuleBtn.disabled = true;
        }
    });

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            yamlUploadInput.files = files;
            selectedFileNameDisplay.textContent = `已选择: ${files[0].name}`;
            uploadRuleBtn.disabled = false;
        }
    });

    dropZone.addEventListener('click', (e) => {
        if (e.target !== selectFileBtn) {
            yamlUploadInput.click();
        }
    });

    uploadRuleBtn.addEventListener('click', async () => {
        const file = yamlUploadInput.files[0];
        if (!file) {
            showToast('请选择一个 YAML 文件上传', 'warning');
            return;
        }
        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await api.uploadRule(formData);
            if (response.ok) {
                showToast('规则上传成功！', 'success');
                yamlUploadInput.value = '';
                selectedFileNameDisplay.textContent = '';
                uploadRuleBtn.disabled = true;
                window.location.hash = 'rules';
            } else {
                const errorData = await response.json();
                showToast(`上传失败: ${errorData.msg}`, 'error');
            }
        } catch (error) {
            console.error('上传错误:', error);
        }
    });

    submitYamlTextBtn.addEventListener('click', async () => {
        const content = yamlTextInput.value.trim();
        if (!content) {
            showToast('请输入 YAML 规则内容', 'warning');
            return;
        }
        try {
            await api.uploadRuleText(content);
            showToast('规则提交成功！', 'success');
            yamlTextInput.value = '';
            window.location.hash = 'rules';
        } catch (error) {
            console.error('提交错误:', error);
        }
    });

    // --- Event Handlers: Scans ---
    scanTagsInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            const tag = scanTagsInput.value.trim();
            if (tag) {
                // 检查标签是否存在于已发布的标签中
                const tagExists = state.publishedTags.some(
                    t => t.toLowerCase() === tag.toLowerCase()
                );
                if (tagExists) {
                    // 使用原始大小写的标签名
                    const originalTag = state.publishedTags.find(
                        t => t.toLowerCase() === tag.toLowerCase()
                    );
                    addScanTag(originalTag);
                    scanTagsInput.value = '';
                } else {
                    showToast(`标签 "${tag}" 不存在`, 'warning');
                }
            }
        }
    });

    scanTagsInput.addEventListener('input', () => {
        const val = scanTagsInput.value.trim().toLowerCase();
        renderAvailableTags(val);
    });

    submitScanBtn.addEventListener('click', async () => {
        const targetUrl = scanTargetUrlInput.value.trim();
        const tags = Array.from(selectedScanTagsContainer.querySelectorAll('.tag-item'))
            .map(el => el.dataset.tag);

        if (!targetUrl || tags.length === 0) {
            showToast('请输入目标 URL 并至少选择一个标签', 'warning');
            return;
        }
        try {
            await api.submitScan(targetUrl, tags);
            showToast('扫描任务已成功提交！', 'success');
            scanTargetUrlInput.value = '';  // 只清空 URL，保留标签
            loadScans();
        } catch (error) {
            console.error('扫描提交错误:', error);
        }
    });

    // --- Event Handlers: Users ---
    filterUsersBtn?.addEventListener('click', () => loadUsers(1));
    
    // 用户搜索框回车事件
    document.getElementById('filter-user-search')?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            loadUsers(1);
        }
    });

    addUserBtn?.addEventListener('click', () => {
        document.getElementById('new-user-username').value = '';
        document.getElementById('new-user-password').value = '';
        document.getElementById('new-user-role').value = 'user';
        addUserModal.style.display = 'flex';
    });

    confirmAddUserBtn?.addEventListener('click', async () => {
        const username = document.getElementById('new-user-username').value.trim();
        const password = document.getElementById('new-user-password').value;
        const role = document.getElementById('new-user-role').value;

        if (!username || !password) {
            showToast('请填写用户名和密码', 'warning');
            return;
        }
        try {
            await api.createUser(username, password, role);
            showToast('用户创建成功！', 'success');
            addUserModal.style.display = 'none';
            loadUsers(1);
        } catch (error) {
            console.error('创建用户错误:', error);
        }
    });

    // 编辑用户 - 保存密码修改
    const confirmEditUserBtn = document.getElementById('confirm-edit-user-btn');
    confirmEditUserBtn?.addEventListener('click', async () => {
        const userId = document.getElementById('edit-user-id').value;
        const newPassword = document.getElementById('edit-user-password').value;

        if (!newPassword) {
            showToast('请输入新密码', 'warning');
            return;
        }
        if (newPassword.length < 6) {
            showToast('密码长度至少6位', 'warning');
            return;
        }
        try {
            await api.resetUserPassword(userId, newPassword);
            showToast('密码修改成功！', 'success');
            document.getElementById('edit-user-modal').style.display = 'none';
            loadUsers(state.usersPagination.page);
        } catch (error) {
            console.error('修改密码错误:', error);
        }
    });

    // Modal close handlers
    document.querySelectorAll('.modal-close').forEach(btn => {
        btn.addEventListener('click', () => {
            modal.style.display = 'none';
            addUserModal.style.display = 'none';
            const editUserModal = document.getElementById('edit-user-modal');
            if (editUserModal) editUserModal.style.display = 'none';
        });
    });

    document.querySelectorAll('.modal').forEach(m => {
        m.addEventListener('click', (e) => {
            if (e.target === m) {
                m.style.display = 'none';
            }
        });
    });

    // --- Data Loading ---
    async function loadDashboardStats() {
        try {
            const rulesResult = await api.getRules('', 1, 1);
            const publishedResult = await api.getRules('', 1, 1, 'published', '');
            const scansResult = await api.getScans(1, 1);
            
            statRules.textContent = rulesResult ? rulesResult.total : 0;
            // 单独查询已发布规则数量
            statPublished.textContent = publishedResult ? publishedResult.total : 0;
            statScans.textContent = scansResult ? scansResult.total : 0;

            // 管理员显示待审核用户数
            if (state.role === 'admin') {
                statPendingUsersCard.style.display = 'block';
                const usersResult = await api.getUsers(1, 1, 'pending');
                const pendingCount = usersResult ? usersResult.total : 0;
                statPendingUsers.textContent = pendingCount;
            }
        } catch (error) {
            console.error('加载统计数据失败:', error);
        }
    }

    async function loadRules(page = 1) {
        const filterText = filterTagsInput.value.trim();
        const statusFilter = document.getElementById('filter-status-select')?.value || '';
        try {
            // 获取规则（分页，后端筛选）
            const result = await api.getRules('', page, state.rulesPagination.perPage, statusFilter, filterText);
            
            state.rules = result.rules || [];
            state.rulesPagination = {
                ...state.rulesPagination,
                page: result.page,
                total: result.total,
                pages: result.pages
            };
            
            renderRules(state.rules);
            renderPagination('rules', state.rulesPagination, loadRules);
        } catch (error) {
            console.error('加载规则失败:', error);
        }
    }

    let scanPollingTimer = null;

    async function loadScans(page = 1) {
        try {
            const result = await api.getScans(page, state.scansPagination.perPage);
            const scans = result.tasks || [];
            
            state.scansPagination = {
                ...state.scansPagination,
                page: result.page,
                total: result.total,
                pages: result.pages
            };
            
            renderScans(scans);
            renderPagination('scans', state.scansPagination, loadScans);
            
            // 检查是否有 running 状态的任务，如果有则自动轮询
            const hasRunning = scans && scans.some(s => s.status === 'running');
            if (hasRunning) {
                startScanPolling();
            } else {
                stopScanPolling();
            }
        } catch (error) {
            console.error('加载扫描任务失败:', error);
        }
    }

    function startScanPolling() {
        if (scanPollingTimer) return; // 已经在轮询了
        scanPollingTimer = setInterval(async () => {
            try {
                const result = await api.getScans(state.scansPagination.page, state.scansPagination.perPage);
                const scans = result.tasks || [];
                renderScans(scans);
                
                // 如果没有 running 的任务了，停止轮询
                const hasRunning = scans && scans.some(s => s.status === 'running');
                if (!hasRunning) {
                    stopScanPolling();
                }
            } catch (error) {
                console.error('轮询扫描任务失败:', error);
            }
        }, 3000); // 每3秒刷新一次
    }

    function stopScanPolling() {
        if (scanPollingTimer) {
            clearInterval(scanPollingTimer);
            scanPollingTimer = null;
        }
    }

    async function loadPublishedTags() {
        try {
            // 默认只加载前10个最常用标签
            const tags = await api.getPublishedTags(false);
            state.publishedTags = tags || [];
            renderAvailableTags('');
        } catch (error) {
            console.error('加载标签失败:', error);
        }
    }

    async function loadUsers(page = 1) {
        try {
            const statusFilter = filterUserStatus?.value || '';
            const searchFilter = document.getElementById('filter-user-search')?.value || '';
            const result = await api.getUsers(page, state.usersPagination.perPage, statusFilter, searchFilter);
            state.users = result.users || [];
            state.usersPagination = {
                ...state.usersPagination,
                page: result.page,
                total: result.total,
                pages: result.pages
            };
            renderUsers(state.users);
            renderPagination('users', state.usersPagination, loadUsers);
        } catch (error) {
            console.error('加载用户失败:', error);
        }
    }
    
    // --- 分页渲染函数 ---
    function renderPagination(type, pagination, loadFunction) {
        const containerId = `${type}-pagination`;
        let container = document.getElementById(containerId);
        
        // 如果容器不存在，创建它
        if (!container) {
            const tableContainer = document.querySelector(`#${type}-view .table-container`) || 
                                   document.querySelector(`#${type}-table`)?.parentElement;
            if (tableContainer) {
                container = document.createElement('div');
                container.id = containerId;
                container.className = 'pagination-container';
                tableContainer.after(container);
            } else {
                return;
            }
        }
        
        // 即使只有一页也显示分页信息（包含每页数量选择）
        if (pagination.total === 0) {
            container.innerHTML = '';
            return;
        }
        
        let html = '<div class="pagination">';
        
        // 上一页
        html += `<button class="page-btn" ${pagination.page <= 1 ? 'disabled' : ''} data-page="${pagination.page - 1}">&laquo;</button>`;
        
        // 页码
        const maxButtons = 5;
        let startPage = Math.max(1, pagination.page - Math.floor(maxButtons / 2));
        let endPage = Math.min(pagination.pages, startPage + maxButtons - 1);
        
        if (endPage - startPage < maxButtons - 1) {
            startPage = Math.max(1, endPage - maxButtons + 1);
        }
        
        if (pagination.pages > 1) {
            if (startPage > 1) {
                html += `<button class="page-btn" data-page="1">1</button>`;
                if (startPage > 2) {
                    html += `<span class="page-ellipsis">...</span>`;
                }
            }
            
            for (let i = startPage; i <= endPage; i++) {
                html += `<button class="page-btn ${i === pagination.page ? 'active' : ''}" data-page="${i}">${i}</button>`;
            }
            
            if (endPage < pagination.pages) {
                if (endPage < pagination.pages - 1) {
                    html += `<span class="page-ellipsis">...</span>`;
                }
                html += `<button class="page-btn" data-page="${pagination.pages}">${pagination.pages}</button>`;
            }
        } else {
            html += `<button class="page-btn active" data-page="1">1</button>`;
        }
        
        // 下一页
        html += `<button class="page-btn" ${pagination.page >= pagination.pages ? 'disabled' : ''} data-page="${pagination.page + 1}">&raquo;</button>`;
        
        // 分隔符
        html += `<span class="pagination-divider">|</span>`;
        
        // 每页显示数量下拉框（放在页码右边）
        html += `<select class="page-size-select" data-type="${type}">`;
        [10, 20, 50, 100, 500, 1000].forEach(size => {
            html += `<option value="${size}" ${pagination.perPage === size ? 'selected' : ''}>${size}条/页</option>`;
        });
        html += `</select>`;
        
        // 总数信息
        html += `<span class="pagination-info">共${pagination.total}条</span>`;
        
        html += '</div>';
        
        container.innerHTML = html;
        
        // 绑定页码点击事件
        container.querySelectorAll('.page-btn:not([disabled])').forEach(btn => {
            btn.onclick = () => {
                const page = parseInt(btn.dataset.page);
                if (page && page !== pagination.page) {
                    loadFunction(page);
                }
            };
        });
        
        // 绑定每页数量选择事件
        const pageSizeSelect = container.querySelector('.page-size-select');
        if (pageSizeSelect) {
            pageSizeSelect.onchange = (e) => {
                const newPerPage = parseInt(e.target.value);
                const paginationType = e.target.dataset.type;
                
                // 更新对应的分页状态
                if (paginationType === 'rules') {
                    state.rulesPagination.perPage = newPerPage;
                } else if (paginationType === 'users') {
                    state.usersPagination.perPage = newPerPage;
                } else if (paginationType === 'scans') {
                    state.scansPagination.perPage = newPerPage;
                }
                
                // 重新加载第一页
                loadFunction(1);
            };
        }
    }

    // --- Rendering ---
    function renderRules(rules) {
        rulesTableBody.innerHTML = '';
        
        // 清空选择状态
        selectedRuleIds.clear();
        updateBatchToolbar();
        
        // 更新全选框
        const selectAllCheckbox = document.getElementById('select-all-rules');
        if (selectAllCheckbox) {
            selectAllCheckbox.checked = false;
        }
        
        if (!rules || rules.length === 0) {
            const colSpan = (state.role === 'user') ? 6 : 7;
            rulesTableBody.innerHTML = `<tr><td colspan="${colSpan}" style="text-align: center; color: #999;">没有找到规则</td></tr>`;
            return;
        }
        rules.forEach(rule => {
            const row = createRuleRow(rule);
            rulesTableBody.appendChild(row);
        });
    }

    function createRuleRow(rule) {
        const row = document.createElement('tr');
        row.id = `rule-row-${rule.id}`;

        const userRole = state.role || 'user';
        const isOwner = rule.uploaded_by === state.username;
        const canEditTags = (userRole === 'admin') || (userRole === 'editor' && isOwner && rule.status !== 'published');
        const canValidate = (userRole === 'admin' || (userRole === 'editor' && isOwner)) && (rule.status === 'pending' || rule.status === 'failed');
        const canPublish = userRole === 'admin' && rule.status === 'verified';
        const canUnpublish = userRole === 'admin' && rule.status === 'published';
        const canDelete = userRole === 'admin';

        // Checkbox cell (for admin/editor only)
        if (userRole !== 'user') {
            const checkboxCell = document.createElement('td');
            checkboxCell.className = 'checkbox-cell';
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'rule-checkbox';
            checkbox.dataset.ruleId = rule.id;
            checkbox.checked = selectedRuleIds.has(rule.id);
            checkbox.onchange = () => handleRuleCheckboxChange(rule.id, checkbox.checked);
            checkboxCell.appendChild(checkbox);
            row.appendChild(checkboxCell);
        }

        // Name cell - 处理长名称
        const nameCell = document.createElement('td');
        nameCell.className = 'rule-name-cell';
        nameCell.textContent = rule.name;
        nameCell.title = rule.name;  // 悬停显示完整名称

        // Tags cell
        const tagsCell = document.createElement('td');
        tagsCell.className = 'tags-cell';

        rule.tags.forEach(tag => {
            const tagEl = document.createElement('span');
            tagEl.className = 'tag-item';
            tagEl.textContent = tag;
            if (canEditTags) {
                const removeBtn = document.createElement('span');
                removeBtn.className = 'remove-tag';
                removeBtn.textContent = '×';
                removeBtn.onclick = (e) => {
                    e.stopPropagation();
                    removeTag(rule.id, tag);
                };
                tagEl.appendChild(removeBtn);
            }
            tagsCell.appendChild(tagEl);
        });

        if (canEditTags) {
            const addBtn = document.createElement('span');
            addBtn.className = 'add-tag-btn';
            addBtn.textContent = '+';
            addBtn.onclick = () => showAddTagInput(addBtn, rule.id);
            tagsCell.appendChild(addBtn);
        }

        // Other cells
        const uploaderCell = document.createElement('td');
        uploaderCell.textContent = rule.uploaded_by;

        const timeCell = document.createElement('td');
        timeCell.textContent = new Date(rule.uploaded_at).toLocaleString();

        const statusCell = document.createElement('td');
        const statusBadge = document.createElement('span');
        statusBadge.className = `status status-${rule.status}`;
        statusBadge.textContent = rule.status;
        statusCell.appendChild(statusBadge);

        // Actions cell
        const actionsCell = document.createElement('td');
        actionsCell.className = 'actions-cell';

        // 查看按钮 - 所有人可用
        const viewBtn = document.createElement('button');
        viewBtn.className = 'action-btn btn-secondary btn-small';
        viewBtn.textContent = '查看';
        viewBtn.onclick = () => showRuleContent(rule.id);
        actionsCell.appendChild(viewBtn);

        if (canValidate) {
            const btn = document.createElement('button');
            btn.className = 'action-btn btn-primary btn-small';
            btn.textContent = '验证';
            btn.onclick = () => handleRuleAction('validate', rule.id);
            actionsCell.appendChild(btn);
        }
        if (canPublish) {
            const btn = document.createElement('button');
            btn.className = 'action-btn btn-primary btn-small';
            btn.textContent = '发布';
            btn.onclick = () => handleRuleAction('publish', rule.id);
            actionsCell.appendChild(btn);
        }
        if (canUnpublish) {
            const btn = document.createElement('button');
            btn.className = 'action-btn action-btn-secondary btn-small';
            btn.textContent = '下架';
            btn.onclick = () => handleRuleAction('unpublish', rule.id);
            actionsCell.appendChild(btn);
        }
        if (canDelete) {
            const btn = document.createElement('button');
            btn.className = 'action-btn action-btn-danger btn-small';
            btn.textContent = '删除';
            btn.onclick = () => handleRuleAction('delete', rule.id);
            actionsCell.appendChild(btn);
        }

        row.appendChild(nameCell);
        row.appendChild(tagsCell);
        row.appendChild(uploaderCell);
        row.appendChild(timeCell);
        row.appendChild(statusCell);
        row.appendChild(actionsCell);

        return row;
    }

    function renderScans(scans) {
        scansTableBody.innerHTML = '';
        if (!scans || scans.length === 0) {
            scansTableBody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: #999;">没有找到扫描任务</td></tr>';
            return;
        }
        scans.forEach(scan => {
            const row = document.createElement('tr');
            let findingsCount = '-';
            if (scan.findings_summary && typeof scan.findings_summary === 'object') {
                findingsCount = scan.findings_summary.total || 0;
            } else if (scan.status === 'completed') {
                findingsCount = 0;
            }

            // 将标签渲染为高亮样式
            let tagsHtml = '';
            if (Array.isArray(scan.tags) && scan.tags.length > 0) {
                tagsHtml = scan.tags.map(tag => 
                    `<span class="tag-item">${tag}</span>`
                ).join('');
            } else if (scan.tags) {
                tagsHtml = `<span class="tag-item">${scan.tags}</span>`;
            }

            row.innerHTML = `
                <td>${scan.id}</td>
                <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis;" title="${scan.target_url}">${scan.target_url}</td>
                <td class="tags-cell">${tagsHtml}</td>
                <td><span class="status status-${scan.status}">${scan.status}</span></td>
                <td>${scan.initiated_by}</td>
                <td>${new Date(scan.created_at).toLocaleString()}</td>
                <td>${findingsCount}</td>
                <td><button class="action-btn btn-secondary btn-small">详情</button></td>
            `;
            row.querySelector('button').onclick = () => showScanDetails(scan.id);
            scansTableBody.appendChild(row);
        });
    }

    function renderUsers(users) {
        usersTableBody.innerHTML = '';
        
        // 后端已经做了状态筛选，这里直接使用
        if (!users || users.length === 0) {
            usersTableBody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #999;">没有找到用户</td></tr>';
            return;
        }
        
        const roleText = {
            'admin': '管理员',
            'editor': '编辑',
            'user': '用户'
        };
        
        users.forEach(user => {
            const row = document.createElement('tr');
            
            const statusClass = {
                'pending': 'status-pending',
                'approved': 'status-published',
                'rejected': 'status-failed'
            }[user.status] || '';

            const statusText = {
                'pending': '待审核',
                'approved': '已通过',
                'rejected': '已拒绝'
            }[user.status] || user.status;

            row.innerHTML = `
                <td>${user.id}</td>
                <td>${user.username}</td>
                <td>${roleText[user.role] || user.role}</td>
                <td><span class="status ${statusClass}">${statusText}</span></td>
                <td>${user.created_at ? new Date(user.created_at).toLocaleString() : '-'}</td>
                <td class="actions-cell"></td>
            `;

            const actionsCell = row.querySelector('.actions-cell');
            
            if (user.status === 'pending') {
                const approveBtn = document.createElement('button');
                approveBtn.className = 'action-btn btn-primary btn-small';
                approveBtn.textContent = '通过';
                approveBtn.onclick = () => handleUserAction('approve', user.id);
                actionsCell.appendChild(approveBtn);

                const rejectBtn = document.createElement('button');
                rejectBtn.className = 'action-btn action-btn-danger btn-small';
                rejectBtn.textContent = '拒绝';
                rejectBtn.onclick = () => handleUserAction('reject', user.id);
                actionsCell.appendChild(rejectBtn);
            }

            // 编辑按钮 - 可以修改密码（admin用户除外）
            if (user.username !== 'admin') {
                const editBtn = document.createElement('button');
                editBtn.className = 'action-btn btn-secondary btn-small';
                editBtn.textContent = '编辑';
                editBtn.onclick = () => showEditUserModal(user);
                actionsCell.appendChild(editBtn);
            }

            if (user.username !== 'admin') {
                const deleteBtn = document.createElement('button');
                deleteBtn.className = 'action-btn action-btn-danger btn-small';
                deleteBtn.textContent = '删除';
                deleteBtn.onclick = () => handleUserAction('delete', user.id);
                actionsCell.appendChild(deleteBtn);
            }

            usersTableBody.appendChild(row);
        });
    }

    // 显示编辑用户模态框
    function showEditUserModal(user) {
        const editUserModal = document.getElementById('edit-user-modal');
        document.getElementById('edit-user-id').value = user.id;
        document.getElementById('edit-user-username').value = user.username;
        document.getElementById('edit-user-password').value = '';
        editUserModal.style.display = 'flex';
    }

    function renderAvailableTags(filter) {
        availableTagsList.innerHTML = '';
        
        const selectedTags = Array.from(selectedScanTagsContainer.querySelectorAll('.tag-item'))
            .map(el => el.dataset.tag);

        const filtered = state.publishedTags.filter(tag => {
            const matchFilter = !filter || tag.toLowerCase().includes(filter);
            const notSelected = !selectedTags.includes(tag);
            return matchFilter && notSelected;
        });

        if (filtered.length === 0) {
            availableTagsList.innerHTML = '<span class="hint-text">没有可用标签</span>';
            return;
        }

        filtered.forEach(tag => {
            const tagEl = document.createElement('span');
            tagEl.className = 'tag-option';
            tagEl.textContent = tag;
            tagEl.onclick = () => {
                addScanTag(tag);
                scanTagsInput.value = '';
                renderAvailableTags('');
            };
            availableTagsList.appendChild(tagEl);
        });
    }

    function addScanTag(tag) {
        const existing = selectedScanTagsContainer.querySelector(`[data-tag="${tag}"]`);
        if (existing) return;

        const tagEl = document.createElement('span');
        tagEl.className = 'tag-item';
        tagEl.dataset.tag = tag;
        tagEl.textContent = tag;

        const removeBtn = document.createElement('span');
        removeBtn.className = 'remove-tag';
        removeBtn.textContent = '×';
        removeBtn.onclick = () => {
            tagEl.remove();
            renderAvailableTags(scanTagsInput.value.trim().toLowerCase());
        };

        tagEl.appendChild(removeBtn);
        selectedScanTagsContainer.appendChild(tagEl);
        renderAvailableTags('');
    }

    // --- Action Handlers ---
    async function handleRuleAction(action, ruleId) {
        try {
            let result;
            switch (action) {
                case 'validate':
                    result = await api.validateRule(ruleId);
                    showToast(result.msg || '验证成功', 'success');
                    updateRuleInState(result.rule);
                    break;
                case 'publish':
                    result = await api.publishRule(ruleId);
                    showToast(result.msg || '发布成功', 'success');
                    updateRuleInState(result.rule);
                    break;
                case 'unpublish':
                    result = await api.unpublishRule(ruleId);
                    showToast(result.msg || '下架成功', 'success');
                    updateRuleInState(result.rule);
                    break;
                case 'delete':
                    if (confirm('确定要删除这个规则吗？')) {
                        await api.deleteRule(ruleId);
                        showToast('规则已删除', 'success');
                        loadRules(state.rulesPagination.page);
                    }
                    break;
            }
        } catch (error) {
            console.error(`操作失败: ${action}`, error);
            if (error.rule) updateRuleInState(error.rule);
        }
    }

    async function handleUserAction(action, userId) {
        try {
            switch (action) {
                case 'approve':
                    await api.approveUser(userId);
                    showToast('用户已通过审核', 'success');
                    loadUsers(state.usersPagination.page);
                    break;
                case 'reject':
                    await api.rejectUser(userId);
                    showToast('用户申请已拒绝', 'info');
                    loadUsers(state.usersPagination.page);
                    break;
                case 'delete':
                    if (confirm('确定要删除这个用户吗？')) {
                        await api.deleteUser(userId);
                        showToast('用户已删除', 'success');
                        loadUsers(state.usersPagination.page);
                    }
                    break;
            }
        } catch (error) {
            console.error(`用户操作失败: ${action}`, error);
        }
    }

    async function removeTag(ruleId, tagToRemove) {
        const rule = state.rules.find(r => r.id === ruleId);
        if (!rule) return;
        const updatedTags = rule.tags.filter(t => t !== tagToRemove);
        try {
            const result = await api.updateRule(ruleId, { tags: updatedTags });
            updateRuleInState(result.rule);
        } catch (error) {
            console.error('删除标签失败:', error);
        }
    }

    function showAddTagInput(btn, ruleId) {
        const container = btn.parentNode;
        const existingInput = container.querySelector('.tag-input-inline');
        if (existingInput) {
            existingInput.focus();
            return;
        }

        // 隐藏添加按钮
        btn.style.display = 'none';

        const input = document.createElement('input');
        input.type = 'text';
        input.className = 'tag-input-inline';
        input.placeholder = '输入标签，逗号分割，回车确认';

        const addTags = async () => {
            const rule = state.rules.find(r => r.id === ruleId);
            if (!rule) return;
            const newTags = input.value.split(/[,，]/).map(t => t.trim()).filter(t => t && !rule.tags.includes(t));
            if (newTags.length > 0) {
                const updatedTags = [...rule.tags, ...newTags];
                try {
                    const result = await api.updateRule(ruleId, { tags: updatedTags });
                    updateRuleInState(result.rule);
                } catch (error) {
                    console.error('添加标签失败:', error);
                }
            }
            input.remove();
            // 重新显示添加按钮
            btn.style.display = '';
        };

        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                addTags();
            }
            if (e.key === 'Escape') {
                input.remove();
                btn.style.display = '';
            }
        });
        input.addEventListener('blur', () => setTimeout(addTags, 100));

        container.insertBefore(input, btn);
        input.focus();
    }

    function updateRuleInState(updatedRule) {
        const index = state.rules.findIndex(r => r.id === updatedRule.id);
        if (index !== -1) {
            state.rules[index] = updatedRule;
        }
        const oldRow = document.getElementById(`rule-row-${updatedRule.id}`);
        if (oldRow) {
            const newRow = createRuleRow(updatedRule);
            oldRow.replaceWith(newRow);
        }
    }

    async function showRuleContent(ruleId) {
        try {
            const data = await api.getRuleContent(ruleId);
            modalTitle.textContent = `规则: ${data.rule.name}`;
            modalBody.innerHTML = `
                <div style="margin-bottom: 1rem; display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span class="status status-${data.rule.status}">${data.rule.status}</span>
                        <span style="margin-left: 1rem; color: #666;">上传者: ${data.rule.uploaded_by}</span>
                    </div>
                    <button class="btn-copy" onclick="copyRuleContent(this)" data-content="${encodeURIComponent(data.content)}">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                        复制
                    </button>
                </div>
                <pre style="background: #f5f7fa; padding: 1rem; border-radius: 8px; overflow-x: auto; font-size: 0.85rem; line-height: 1.5; max-height: 60vh; overflow-y: auto;">${escapeHtml(data.content)}</pre>
            `;
            modal.style.display = 'flex';
        } catch (error) {
            console.error('获取规则内容失败:', error);
        }
    }

    // 复制规则内容到剪贴板
    window.copyRuleContent = function(btn) {
        const content = btn.dataset.content ? decodeURIComponent(btn.dataset.content) : '';
        if (!content) {
            console.error('没有可复制的内容');
            return;
        }
        
        // 优先使用 clipboard API，降级使用 execCommand
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(content).then(() => {
                showCopyToast();
            }).catch(err => {
                console.error('复制失败:', err);
                fallbackCopy(content);
            });
        } else {
            fallbackCopy(content);
        }
    }
    
    // 降级复制方案
    function fallbackCopy(content) {
        const textarea = document.createElement('textarea');
        textarea.value = content;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
            showCopyToast();
        } catch (err) {
            console.error('降级复制也失败:', err);
        }
        document.body.removeChild(textarea);
    }

    function showCopyToast() {
        const toast = document.getElementById('copy-toast');
        toast.classList.add('show');
        setTimeout(() => {
            toast.classList.remove('show');
        }, 2000);
    }

    async function showScanDetails(scanId) {
        try {
            const summary = await api.getScanSummary(scanId);
            const tags = Array.isArray(summary.tags) ? summary.tags.join(', ') : (summary.tags || '-');

            let html = `
                <div style="margin-bottom: 1rem;">
                    <p><strong>目标:</strong> ${summary.target_url || '-'}</p>
                    <p><strong>状态:</strong> <span class="status status-${summary.status}">${summary.status}</span></p>
                    <p><strong>标签:</strong> ${tags}</p>
                </div>
            `;

            if (summary.error_log) {
                html += `
                    <div style="margin-bottom: 1rem;">
                        <strong>错误日志:</strong>
                        <pre style="background: #f5f5f5; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 0.85rem;">${escapeHtml(summary.error_log)}</pre>
                    </div>
                `;
            }

            if (summary.findings && summary.findings.length > 0) {
                html += `<strong>发现的漏洞 (${summary.findings.length}):</strong>`;
                summary.findings.forEach(f => {
                    const severity = f.severity || 'info';
                    const templateId = f['template-id'] || f.template_id || 'Unknown';
                    const matchedAt = f['matched-at'] || f.matched_url || '-';
                    const description = f.description || '';
                    html += `
                        <div class="vuln-item ${severity}">
                            <strong>${templateId}</strong> <span class="status status-${severity}">${severity}</span>
                            <div><small>URL: ${matchedAt}</small></div>
                            ${description ? `<div><small>${escapeHtml(description)}</small></div>` : ''}
                        </div>
                    `;
                });
            } else {
                html += '<p style="color: #999; margin-top: 1rem;">未发现漏洞。</p>';
            }

            modalTitle.textContent = `扫描 #${scanId} 详情`;
            modalBody.innerHTML = html;
            modal.style.display = 'flex';
        } catch (error) {
            console.error('获取扫描详情失败:', error);
        }
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // --- User Menu Dropdown ---
    const userMenuBtn = document.getElementById('user-menu-btn');
    const userDropdown = document.getElementById('user-dropdown');
    const userMenu = document.querySelector('.user-menu');
    const profileBtn = document.getElementById('profile-btn');
    const profileModal = document.getElementById('profile-modal');

    if (userMenuBtn && userMenu) {
        userMenuBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            userMenu.classList.toggle('open');
        });

        // 点击其他地方关闭下拉菜单
        document.addEventListener('click', (e) => {
            if (!userMenu.contains(e.target)) {
                userMenu.classList.remove('open');
            }
        });
    }

    // --- Profile Modal ---
    if (profileBtn) {
        profileBtn.addEventListener('click', async (e) => {
            e.preventDefault();
            userMenu.classList.remove('open');
            await loadProfile();
            if (profileModal) profileModal.style.display = 'flex';
        });
    }

    // 关闭个人设置模态框
    if (profileModal) {
        const closeBtn = profileModal.querySelector('.modal-close');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                profileModal.style.display = 'none';
                clearProfileForm();
            });
        }
        profileModal.addEventListener('click', (e) => {
            if (e.target === profileModal) {
                profileModal.style.display = 'none';
                clearProfileForm();
            }
        });
    }

    async function loadProfile() {
        try {
            const profile = await api.request('/profile');
            document.getElementById('profile-username').textContent = profile.username || '-';
            document.getElementById('profile-role').textContent = translateRole(profile.role) || '-';
            document.getElementById('profile-created').textContent = profile.created_at ? 
                new Date(profile.created_at).toLocaleString('zh-CN') : '-';
        } catch (error) {
            console.error('加载个人资料失败:', error);
        }
    }

    function translateRole(role) {
        const roles = {
            'admin': '管理员',
            'editor': '编辑',
            'user': '用户'
        };
        return roles[role] || role;
    }

    function clearProfileForm() {
        const currentPwd = document.getElementById('profile-current-password');
        const newPwd = document.getElementById('profile-new-password');
        const confirmPwd = document.getElementById('profile-confirm-password');
        if (currentPwd) currentPwd.value = '';
        if (newPwd) newPwd.value = '';
        if (confirmPwd) confirmPwd.value = '';
    }

    // 保存个人资料（修改密码）
    const saveProfileBtn = document.getElementById('save-profile-btn');
    if (saveProfileBtn) {
        saveProfileBtn.addEventListener('click', async () => {
            const currentPassword = document.getElementById('profile-current-password').value;
            const newPassword = document.getElementById('profile-new-password').value;
            const confirmPassword = document.getElementById('profile-confirm-password').value;

            if (!newPassword) {
                showToast('请输入新密码', 'warning');
                return;
            }

            if (newPassword.length < 6) {
                showToast('新密码长度至少6位', 'warning');
                return;
            }

            if (newPassword !== confirmPassword) {
                showToast('两次输入的密码不一致', 'warning');
                return;
            }

            if (!currentPassword) {
                showToast('请输入当前密码', 'warning');
                return;
            }

            try {
                await api.request('/profile', {
                    method: 'PUT',
                    body: JSON.stringify({
                        current_password: currentPassword,
                        new_password: newPassword
                    })
                });
                showToast('密码修改成功', 'success');
                profileModal.style.display = 'none';
                clearProfileForm();
            } catch (error) {
                showToast(error.msg || '密码修改失败', 'error');
            }
        });
    }

    // --- System Settings ---
    async function loadSettings() {
        try {
            const settings = await api.request('/settings');
            
            document.getElementById('current-nuclei-path').textContent = settings.nuclei_path || '-';
            
            const platformNames = { 'windows': 'Windows', 'linux': 'Linux', 'darwin': 'macOS' };
            document.getElementById('current-nuclei-platform').textContent = 
                platformNames[settings.nuclei_platform] || settings.nuclei_platform || '-';
            
            const statusEl = document.getElementById('nuclei-status');
            if (settings.nuclei_exists) {
                statusEl.textContent = '可用';
                statusEl.className = 'status-badge available';
            } else {
                statusEl.textContent = '不可用';
                statusEl.className = 'status-badge unavailable';
            }
            
            document.getElementById('nuclei-version').textContent = '-';
            
            // 加载 SSL 设置
            loadSSLSettings();
        } catch (error) {
            console.error('加载设置失败:', error);
            showToast('加载设置失败', 'error');
        }
    }
    
    // 加载 SSL 证书设置
    async function loadSSLSettings() {
        try {
            const ssl = await api.request('/settings/ssl');
            
            // HTTPS 状态下拉框
            const httpsSelect = document.getElementById('https-enabled-select');
            if (httpsSelect) {
                httpsSelect.value = ssl.https_enabled ? 'true' : 'false';
                
                // 绑定 change 事件 - 选择时直接保存
                httpsSelect.onchange = async () => {
                    const enabled = httpsSelect.value === 'true';
                    const hintEl = document.getElementById('https-save-hint');
                    
                    httpsSelect.disabled = true;
                    
                    try {
                        const result = await api.request('/settings/ssl/toggle', {
                            method: 'POST',
                            body: JSON.stringify({ enabled: enabled })
                        });
                        showToast(result.msg, 'success');
                        
                        // 显示保存提示
                        if (hintEl) {
                            hintEl.style.display = 'inline';
                            hintEl.textContent = '已保存，重启生效';
                            hintEl.style.color = '#27ae60';
                        }
                    } catch (error) {
                        showToast(error.msg || '保存失败', 'error');
                        // 恢复原值
                        httpsSelect.value = ssl.https_enabled ? 'true' : 'false';
                        
                        if (hintEl) {
                            hintEl.style.display = 'inline';
                            hintEl.textContent = error.msg || '保存失败';
                            hintEl.style.color = '#e74c3c';
                        }
                    } finally {
                        httpsSelect.disabled = false;
                    }
                };
            }
            
            // 证书状态
            const certStatusEl = document.getElementById('ssl-cert-status');
            if (certStatusEl) {
                certStatusEl.textContent = ssl.cert_exists ? '✓ 已上传' : '✗ 未上传';
                certStatusEl.style.color = ssl.cert_exists ? '#27ae60' : '#e74c3c';
            }
            
            // 私钥状态
            const keyStatusEl = document.getElementById('ssl-key-status');
            if (keyStatusEl) {
                keyStatusEl.textContent = ssl.key_exists ? '✓ 已上传' : '✗ 未上传';
                keyStatusEl.style.color = ssl.key_exists ? '#27ae60' : '#e74c3c';
            }
            
            // 证书详情
            const certInfoEl = document.getElementById('ssl-cert-info');
            if (certInfoEl && ssl.cert_info && !ssl.cert_info.error && !ssl.cert_info.note) {
                certInfoEl.style.display = 'block';
                document.getElementById('ssl-cert-subject').textContent = ssl.cert_info.subject || '-';
                document.getElementById('ssl-cert-issuer').textContent = ssl.cert_info.issuer || '-';
                
                const notBefore = ssl.cert_info.not_before ? new Date(ssl.cert_info.not_before).toLocaleString() : '-';
                const notAfter = ssl.cert_info.not_after ? new Date(ssl.cert_info.not_after).toLocaleString() : '-';
                document.getElementById('ssl-cert-validity').textContent = `${notBefore} 至 ${notAfter}`;
            } else if (certInfoEl) {
                certInfoEl.style.display = 'none';
            }
        } catch (error) {
            console.error('加载SSL设置失败:', error);
        }
    }
    
    // 生成自签名证书
    const generateSSLBtn = document.getElementById('generate-ssl-btn');
    if (generateSSLBtn) {
        generateSSLBtn.addEventListener('click', async () => {
            const commonName = prompt('请输入域名（Common Name）:', 'localhost');
            if (!commonName) return;
            
            generateSSLBtn.disabled = true;
            generateSSLBtn.textContent = '生成中...';
            
            try {
                const result = await api.request('/settings/ssl/generate', {
                    method: 'POST',
                    body: JSON.stringify({ common_name: commonName, days_valid: 365 })
                });
                showToast(result.msg, 'success');
                loadSSLSettings();
            } catch (error) {
                showToast(error.msg || '生成证书失败', 'error');
            } finally {
                generateSSLBtn.disabled = false;
                generateSSLBtn.textContent = '生成自签名证书';
            }
        });
    }
    
    // 删除证书
    const deleteSSLBtn = document.getElementById('delete-ssl-btn');
    if (deleteSSLBtn) {
        deleteSSLBtn.addEventListener('click', async () => {
            if (!confirm('确定要删除 SSL 证书吗？删除后 HTTPS 将不可用。')) return;
            
            try {
                const result = await api.request('/settings/ssl/delete', { method: 'DELETE' });
                showToast(result.msg, 'success');
                loadSSLSettings();
            } catch (error) {
                showToast(error.msg || '删除失败', 'error');
            }
        });
    }
    
    // 上传 SSL 证书
    const uploadSSLBtn = document.getElementById('upload-ssl-btn');
    const sslCertInput = document.getElementById('ssl-cert-input');
    const sslKeyInput = document.getElementById('ssl-key-input');
    
    if (uploadSSLBtn && sslCertInput && sslKeyInput) {
        uploadSSLBtn.addEventListener('click', async () => {
            const certFile = sslCertInput.files[0];
            const keyFile = sslKeyInput.files[0];
            
            if (!certFile || !keyFile) {
                showToast('请选择证书文件和私钥文件', 'warning');
                return;
            }
            
            uploadSSLBtn.disabled = true;
            uploadSSLBtn.textContent = '上传中...';
            
            try {
                const formData = new FormData();
                formData.append('cert', certFile);
                formData.append('key', keyFile);
                
                const response = await fetch('/api/settings/ssl/upload', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${state.accessToken}`
                    },
                    body: formData
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    showToast(result.msg, 'success');
                    sslCertInput.value = '';
                    sslKeyInput.value = '';
                    loadSSLSettings();
                } else {
                    showToast(result.msg || '上传失败', 'error');
                }
            } catch (error) {
                showToast('上传失败', 'error');
            } finally {
                uploadSSLBtn.disabled = false;
                uploadSSLBtn.textContent = '上传证书';
            }
        });
    }

    // 测试 Nuclei
    const testNucleiBtn = document.getElementById('test-nuclei-btn');
    if (testNucleiBtn) {
        testNucleiBtn.addEventListener('click', async () => {
            testNucleiBtn.disabled = true;
            testNucleiBtn.textContent = '测试中...';
            
            try {
                const result = await api.request('/settings/nuclei/test', { method: 'POST' });
                if (result.success) {
                    showToast('Nuclei 测试成功', 'success');
                    document.getElementById('nuclei-version').textContent = result.version || '-';
                    const statusEl = document.getElementById('nuclei-status');
                    statusEl.textContent = '可用';
                    statusEl.className = 'status-badge available';
                } else {
                    showToast(result.msg || '测试失败', 'error');
                }
            } catch (error) {
                showToast(error.msg || '测试失败', 'error');
            } finally {
                testNucleiBtn.disabled = false;
                testNucleiBtn.textContent = '测试 Nuclei';
            }
        });
    }

    // 重置 Nuclei 设置
    const resetNucleiBtn = document.getElementById('reset-nuclei-btn');
    if (resetNucleiBtn) {
        resetNucleiBtn.addEventListener('click', async () => {
            if (!confirm('确定要重置 Nuclei 设置为默认值吗？')) return;
            
            try {
                await api.request('/settings/nuclei', { method: 'DELETE' });
                showToast('设置已重置', 'success');
                loadSettings();
            } catch (error) {
                showToast(error.msg || '重置失败', 'error');
            }
        });
    }

    // 上传 Nuclei
    const uploadNucleiBtn = document.getElementById('upload-nuclei-btn');
    const nucleiFileInput = document.getElementById('nuclei-file-input');
    const nucleiPlatformSelect = document.getElementById('nuclei-platform-select');

    if (uploadNucleiBtn && nucleiFileInput) {
        uploadNucleiBtn.addEventListener('click', async () => {
            const file = nucleiFileInput.files[0];
            if (!file) {
                showToast('请选择文件', 'warning');
                return;
            }

            const platform = nucleiPlatformSelect ? nucleiPlatformSelect.value : 'windows';
            
            uploadNucleiBtn.disabled = true;
            uploadNucleiBtn.textContent = '上传中...';

            try {
                const formData = new FormData();
                formData.append('file', file);
                formData.append('platform', platform);

                const response = await fetch('/api/settings/nuclei', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${state.accessToken}`
                    },
                    body: formData
                });

                const result = await response.json();
                
                if (response.ok) {
                    showToast('Nuclei 上传成功', 'success');
                    nucleiFileInput.value = '';
                    loadSettings();
                } else {
                    showToast(result.msg || '上传失败', 'error');
                }
            } catch (error) {
                showToast('上传失败', 'error');
            } finally {
                uploadNucleiBtn.disabled = false;
                uploadNucleiBtn.textContent = '上传并配置';
            }
        });
    }

    // 导航到系统设置
    if (navSettings) {
        navSettings.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.hash = 'settings';
        });
    }

    // Initialize
    init();
});
