const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();
 
const app = express();
const PORT = process.env.PORT || 3000;
 
// ===== НАСТРОЙКИ =====
// Включаем детальное логирование для отладки
app.use((req, res, next) => {
    console.log(`📥 ${req.method} ${req.url}`);
    if (req.method === 'POST' || req.method === 'PUT') {
        console.log('📦 Body:', req.body);
    }
    next();
});
 
// CORS - разрешаем все запросы (для разработки)
app.use(cors({
    origin: '*',
    credentials: true
}));
 
app.use(express.json());
 
// ===== БАЗА ДАННЫХ =====
const DB_PATH = path.join(__dirname, 'database', 'db.json');
 
function initDB() {
    const dbDir = path.join(__dirname, 'database');
    if (!fs.existsSync(dbDir)) {
        fs.mkdirSync(dbDir, { recursive: true });
    }
    
    if (!fs.existsSync(DB_PATH)) {
        const initialDB = {
            users: [],
            servers: [],
            admins: ['admin@startup.ru'],
            stats: { totalMatches: 0, totalTournaments: 0, onlineCount: 0 }
        };
        fs.writeFileSync(DB_PATH, JSON.stringify(initialDB, null, 2));
        console.log('✅ База данных создана');
    }
}
 
function readDB() {
    try {
        const data = fs.readFileSync(DB_PATH, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('❌ Ошибка чтения БД:', error);
        return { users: [], servers: [], admins: ['admin@startup.ru'], stats: { totalMatches: 0, totalTournaments: 0, onlineCount: 0 } };
    }
}
 
function writeDB(data) {
    try {
        fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
        return true;
    } catch (error) {
        console.error('❌ Ошибка записи БД:', error);
        return false;
    }
}
 
// ===== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ =====
function findUserByEmail(email) {
    const db = readDB();
    return db.users.find(u => u.email === email);
}
 
function findUserByVKId(vkId) {
    const db = readDB();
    return db.users.find(u => u.vkId === vkId);
}
 
function findUserByUsername(username) {
    const db = readDB();
    return db.users.find(u => u.username === username);
}
 
function generateToken(user) {
    return jwt.sign(
        { id: user.id, email: user.email, username: user.username },
        process.env.JWT_SECRET || 'default_secret_key_change_me',
        { expiresIn: '7d' }
    );
}
 
function verifyToken(token) {
    try {
        return jwt.verify(token, process.env.JWT_SECRET || 'default_secret_key_change_me');
    } catch (error) {
        console.error('❌ Ошибка верификации токена:', error.message);
        return null;
    }
}
 
// ===== MIDDLEWARE =====
function authMiddleware(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Требуется авторизация' });
    }
    
    const decoded = verifyToken(token);
    if (!decoded) {
        return res.status(401).json({ error: 'Неверный токен' });
    }
    
    req.user = decoded;
    next();
}
 
function adminMiddleware(req, res, next) {
    const db = readDB();
    const user = db.users.find(u => u.id === req.user.id);
    if (!user || !db.admins.includes(user.email)) {
        return res.status(403).json({ error: 'Недостаточно прав' });
    }
    next();
}
 
// ===== АУТЕНТИФИКАЦИЯ =====
 
// ===== РЕГИСТРАЦИЯ (исправленная) =====
app.post('/api/auth/register', async (req, res) => {
    console.log('📝 Запрос на регистрацию получен');
    console.log('📦 Тело запроса:', req.body);
    
    try {
        const { username, email, standoffId, password } = req.body;
        
        // ПРОВЕРКА 1: Все поля обязательны
        if (!username || !email || !standoffId || !password) {
            console.log('❌ Ошибка: не все поля заполнены');
            return res.status(400).json({ 
                error: 'Все поля обязательны для заполнения',
                details: { username: !!username, email: !!email, standoffId: !!standoffId, password: !!password }
            });
        }
        
        // ПРОВЕРКА 2: Длина имени
        if (username.length < 3 || username.length > 20) {
            console.log(`❌ Ошибка: имя "${username}" имеет неверную длину (${username.length})`);
            return res.status(400).json({ error: 'Имя должно содержать от 3 до 20 символов' });
        }
        
        // ПРОВЕРКА 3: Формат email
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            console.log(`❌ Ошибка: email "${email}" имеет неверный формат`);
            return res.status(400).json({ error: 'Введите корректный email' });
        }
        
        // ПРОВЕРКА 4: ID только цифры
        if (!/^\d+$/.test(standoffId)) {
            console.log(`❌ Ошибка: ID "${standoffId}" содержит не только цифры`);
            return res.status(400).json({ error: 'ID Standoff 2 должен содержать только цифры' });
        }
        
        // ПРОВЕРКА 5: Длина пароля
        if (password.length < 8) {
            console.log(`❌ Ошибка: пароль слишком короткий (${password.length})`);
            return res.status(400).json({ error: 'Пароль должен содержать минимум 8 символов' });
        }
        
        // ПРОВЕРКА 6: Проверяем, не занят ли email
        const db = readDB();
        if (findUserByEmail(email)) {
            console.log(`❌ Ошибка: email "${email}" уже занят`);
            return res.status(400).json({ error: 'Пользователь с таким email уже существует' });
        }
        
        // ПРОВЕРКА 7: Проверяем, не занято ли имя
        if (findUserByUsername(username)) {
            console.log(`❌ Ошибка: имя "${username}" уже занято`);
            return res.status(400).json({ error: 'Пользователь с таким именем уже существует' });
        }
        
        // ПРОВЕРКА 8: Проверяем, не занят ли ID
        const existingStandoffId = db.users.find(u => u.standoffId === standoffId);
        if (existingStandoffId) {
            console.log(`❌ Ошибка: ID "${standoffId}" уже занят`);
            return res.status(400).json({ error: 'Пользователь с таким ID Standoff 2 уже существует' });
        }
        
        // ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ - СОЗДАЕМ ПОЛЬЗОВАТЕЛЯ
        console.log('✅ Все проверки пройдены, создаем пользователя...');
        
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const newUser = {
            id: uuidv4(),
            username,
            email,
            standoffId,
            password: hashedPassword,
            vkId: null,
            matches: 0,
            kills: 0,
            deaths: 0,
            kdHistory: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            registered: new Date().toISOString(),
            lastLogin: new Date().toISOString()
        };
        
        db.users.push(newUser);
        writeDB(db);
        console.log(`✅ Пользователь "${username}" успешно создан (ID: ${newUser.id})`);
        
        // Генерируем токен
        const token = generateToken(newUser);
        console.log('✅ Токен сгенерирован');
        
        res.json({
            success: true,
            token,
            user: {
                id: newUser.id,
                username: newUser.username,
                email: newUser.email,
                standoffId: newUser.standoffId,
                matches: newUser.matches,
                kills: newUser.kills,
                deaths: newUser.deaths,
                kdHistory: newUser.kdHistory
            }
        });
        
    } catch (error) {
        console.error('❌ Критическая ошибка при регистрации:', error);
        console.error('📋 Стек ошибки:', error.stack);
        res.status(500).json({ 
            error: 'Ошибка сервера при регистрации',
            message: error.message 
        });
    }
});
 
// ===== ВХОД =====
app.post('/api/auth/login', async (req, res) => {
    console.log('📝 Запрос на вход получен');
    console.log('📦 Тело запроса:', req.body);
    
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            console.log('❌ Ошибка: не заполнены email или пароль');
            return res.status(400).json({ error: 'Email и пароль обязательны' });
        }
        
        const user = findUserByEmail(email);
        if (!user) {
            console.log(`❌ Ошибка: пользователь с email "${email}" не найден`);
            return res.status(401).json({ error: 'Неверный email или пароль' });
        }
        
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            console.log(`❌ Ошибка: неверный пароль для пользователя "${email}"`);
            return res.status(401).json({ error: 'Неверный email или пароль' });
        }
        
        console.log(`✅ Пользователь "${user.username}" успешно вошел`);
        
        const db = readDB();
        const userIndex = db.users.findIndex(u => u.id === user.id);
        if (userIndex !== -1) {
            db.users[userIndex].lastLogin = new Date().toISOString();
            writeDB(db);
        }
        
        const token = generateToken(user);
        
        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                standoffId: user.standoffId,
                matches: user.matches,
                kills: user.kills,
                deaths: user.deaths,
                kdHistory: user.kdHistory
            }
        });
    } catch (error) {
        console.error('❌ Ошибка при входе:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
// ===== ВХОД ЧЕРЕЗ VK =====
app.post('/api/auth/vk', async (req, res) => {
    try {
        const { vkId, vkName, vkAvatar } = req.body;
        
        if (!vkId) {
            return res.status(400).json({ error: 'ID VK обязателен' });
        }
        
        console.log(`📝 VK авторизация: ${vkName} (${vkId})`);
        
        let user = findUserByVKId(vkId);
        const db = readDB();
        
        if (!user) {
            console.log('👤 Создаем нового пользователя через VK');
            const username = vkName.replace(/\s/g, '_').toLowerCase();
            let finalUsername = username;
            let counter = 1;
            while (findUserByUsername(finalUsername)) {
                finalUsername = `${username}_${counter}`;
                counter++;
            }
            
            const newUser = {
                id: uuidv4(),
                username: finalUsername,
                email: `${vkId}@vk.com`,
                standoffId: vkId.toString().slice(0, 9),
                password: await bcrypt.hash(`vk_${vkId}`, 10),
                vkId: vkId.toString(),
                vkAvatar: vkAvatar || '',
                matches: 0,
                kills: 0,
                deaths: 0,
                kdHistory: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                registered: new Date().toISOString(),
                lastLogin: new Date().toISOString()
            };
            
            db.users.push(newUser);
            writeDB(db);
            user = newUser;
            console.log(`✅ VK пользователь "${finalUsername}" создан`);
        } else {
            console.log(`✅ VK пользователь найден: ${user.username}`);
            const userIndex = db.users.findIndex(u => u.id === user.id);
            if (userIndex !== -1) {
                db.users[userIndex].lastLogin = new Date().toISOString();
                writeDB(db);
            }
        }
        
        const token = generateToken(user);
        
        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                standoffId: user.standoffId,
                vkId: user.vkId,
                vkAvatar: user.vkAvatar,
                matches: user.matches,
                kills: user.kills,
                deaths: user.deaths,
                kdHistory: user.kdHistory
            }
        });
    } catch (error) {
        console.error('❌ VK auth error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
// ===== ПОЛУЧЕНИЕ ДАННЫХ ПОЛЬЗОВАТЕЛЯ =====
app.get('/api/auth/me', authMiddleware, (req, res) => {
    try {
        const db = readDB();
        const user = db.users.find(u => u.id === req.user.id);
        
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        
        res.json({
            id: user.id,
            username: user.username,
            email: user.email,
            standoffId: user.standoffId,
            vkId: user.vkId,
            vkAvatar: user.vkAvatar,
            matches: user.matches,
            kills: user.kills,
            deaths: user.deaths,
            kdHistory: user.kdHistory,
            registered: user.registered,
            lastLogin: user.lastLogin
        });
    } catch (error) {
        console.error('❌ Get user error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
// ===== СЕРВЕРА =====
app.get('/api/servers', (req, res) => {
    try {
        const db = readDB();
        res.json(db.servers);
    } catch (error) {
        console.error('❌ Get servers error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
app.post('/api/servers', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const { name, lobby, playerId, map } = req.body;
        
        if (!name || !lobby || !playerId || !map) {
            return res.status(400).json({ error: 'Все поля обязательны' });
        }
        
        const db = readDB();
        const newServer = {
            id: Date.now(),
            name,
            lobby,
            playerId,
            map,
            status: 'online',
            createdAt: new Date().toISOString(),
            createdBy: req.user.id
        };
        
        db.servers.push(newServer);
        writeDB(db);
        
        res.json({ success: true, server: newServer });
    } catch (error) {
        console.error('❌ Create server error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
app.delete('/api/servers/:id', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const serverId = parseInt(req.params.id);
        const db = readDB();
        
        db.servers = db.servers.filter(s => s.id !== serverId);
        writeDB(db);
        
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Delete server error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
// ===== АДМИНЫ =====
app.get('/api/admins', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const db = readDB();
        res.json(db.admins);
    } catch (error) {
        console.error('❌ Get admins error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
app.post('/api/admins', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ error: 'Email обязателен' });
        }
        
        const db = readDB();
        const user = db.users.find(u => u.email === email);
        
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        
        if (db.admins.includes(email)) {
            return res.status(400).json({ error: 'Уже администратор' });
        }
        
        db.admins.push(email);
        writeDB(db);
        
        res.json({ success: true, admins: db.admins });
    } catch (error) {
        console.error('❌ Add admin error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
app.delete('/api/admins/:email', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const email = decodeURIComponent(req.params.email);
        const db = readDB();
        
        db.admins = db.admins.filter(e => e !== email);
        writeDB(db);
        
        res.json({ success: true, admins: db.admins });
    } catch (error) {
        console.error('❌ Remove admin error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
// ===== СТАТИСТИКА =====
app.post('/api/users/:userId/stats', authMiddleware, (req, res) => {
    try {
        const userId = req.params.userId;
        const { kills, deaths } = req.body;
        
        if (userId !== req.user.id) {
            return res.status(403).json({ error: 'Недостаточно прав' });
        }
        
        const db = readDB();
        const userIndex = db.users.findIndex(u => u.id === userId);
        
        if (userIndex === -1) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        
        const user = db.users[userIndex];
        user.kills += kills || 0;
        user.deaths += deaths || 0;
        user.matches += 1;
        
        const kd = user.deaths > 0 ? (user.kills / user.deaths) : user.kills;
        user.kdHistory.push(parseFloat(kd.toFixed(2)));
        if (user.kdHistory.length > 10) {
            user.kdHistory.shift();
        }
        
        writeDB(db);
        
        res.json({
            success: true,
            user: {
                id: user.id,
                username: user.username,
                matches: user.matches,
                kills: user.kills,
                deaths: user.deaths,
                kdHistory: user.kdHistory
            }
        });
    } catch (error) {
        console.error('❌ Update stats error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
// ===== ТОП ИГРОКОВ =====
app.get('/api/top-players', (req, res) => {
    try {
        const db = readDB();
        const topPlayers = db.users
            .map(user => ({
                username: user.username,
                standoffId: user.standoffId,
                kills: user.kills,
                matches: user.matches,
                kd: user.deaths > 0 ? (user.kills / user.deaths).toFixed(2) : user.kills.toFixed(2)
            }))
            .sort((a, b) => b.kills - a.kills)
            .slice(0, 10);
        
        res.json(topPlayers);
    } catch (error) {
        console.error('❌ Get top players error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
// ===== СТАТИСТИКА САЙТА =====
app.get('/api/stats', (req, res) => {
    try {
        const db = readDB();
        const onlineCount = Math.floor(Math.random() * 150) + 50;
        
        res.json({
            online: onlineCount,
            tournaments: db.stats.totalTournaments || 0,
            servers: db.servers.length,
            totalUsers: db.users.length
        });
    } catch (error) {
        console.error('❌ Get stats error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
 
// ===== ЗАПУСК =====
initDB();
 
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📁 Database: ${DB_PATH}`);
    console.log(`🔐 JWT_SECRET: ${process.env.JWT_SECRET ? '✅ Установлен' : '❌ НЕ УСТАНОВЛЕН (используется default)'}`);
});
 
// Обработка необработанных ошибок
process.on('uncaughtException', (error) => {
    console.error('🔥 Необработанное исключение:', error);
});
 
process.on('unhandledRejection', (reason, promise) => {
    console.error('🔥 Необработанный rejection:', reason);
});
