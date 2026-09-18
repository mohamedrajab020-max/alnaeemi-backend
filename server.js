// ==============================================================================
// server.js - Backend Engine for Al-Naemi eMaintenance System (Fixed & Secure)
// ==============================================================================
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const multer = require('multer');

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'ALNAEEMI_SECURE_JWT_SECRET_2026';
const ADMIN_SECRET_KEY = process.env.ADMIN_SECRET_KEY || 'AlNaeemi_Master_Admin_Key_9876';

// ------------------------------------------------------------------------------
// 1. Uploads Setup
// ------------------------------------------------------------------------------
const uploadDir = path.join(__dirname, 'uploads/receipts');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, `receipt-${uniqueSuffix}${ext}`);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('مسموح برفع ملفات الصور فقط!'), false);
    }
  }
});

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ------------------------------------------------------------------------------
// 2. Database Connection & Rate Limiter
// ------------------------------------------------------------------------------
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/alnaeemi_db');

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { success: false, message: 'تجاوزت الحد المسموح من طلبات OTP، يرجى المحاولة لاحقاً.' }
});

// ------------------------------------------------------------------------------
// 3. Schemas & Models
// ------------------------------------------------------------------------------

const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  phone: { type: String, required: true, unique: true },
  role: { type: String, enum: ['client', 'provider', 'admin'], default: 'client' },
  profession: String,
  qualification: String,
  experience: String,
  walletBalance: { type: Number, default: 0 },
  location: {
    type: { type: String, default: 'Point' },
    coordinates: [Number]
  },
  isBlocked: { type: Boolean, default: false },
  otp: String,
  otpExpires: Date,
  createdAt: { type: Date, default: Date.now }
});
userSchema.index({ location: '2dsphere' });
const User = mongoose.model('User', userSchema);

const requestSchema = new mongoose.Schema({
  clientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  serviceCategory: String,
  issueType: String,
  description: String,
  mediaUrls: [String],
  scheduledDate: Date,
  address: String,
  location: {
    type: { type: String, default: 'Point' },
    coordinates: [Number]
  },
  status: { 
    type: String, 
    enum: ['pending', 'bidded', 'accepted', 'in_progress', 'completed', 'cancelled'], 
    default: 'pending' 
  },
  acceptedBidder: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  agreedPrice: Number,
  commission: Number,
  paymentMethod: { type: String, enum: ['cash', 'online', 'instapay', 'vodafone_cash'] },
  isUrgent: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});
requestSchema.index({ location: '2dsphere' });
const ServiceRequest = mongoose.model('ServiceRequest', requestSchema);

const bidSchema = new mongoose.Schema({
  requestId: { type: mongoose.Schema.Types.ObjectId, ref: 'ServiceRequest' },
  providerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  price: Number,
  notes: String,
  createdAt: { type: Date, default: Date.now }
});
const Bid = mongoose.model('Bid', bidSchema);

const paymentMethodSchema = new mongoose.Schema({
  vodafoneCashNumber: { type: String, default: '01010057274' },
  instapayAddress: { type: String, default: '01010057274' },
  instructions: { type: String, default: 'يرجى تحويل العمولة المستحقة على الرقم الموضح ثم رفع صورة إيصال التحويل لتسوية محفظتك.' }
});
const PaymentMethod = mongoose.model('PaymentMethod', paymentMethodSchema);

const paymentTransactionSchema = new mongoose.Schema({
  providerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  method: { type: String, enum: ['vodafone_cash', 'instapay'], required: true },
  transactionRef: String,
  receiptImage: String,
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});
const PaymentTransaction = mongoose.model('PaymentTransaction', paymentTransactionSchema);

const systemSettingsSchema = new mongoose.Schema({
  isAppActive: { type: Boolean, default: true },
  minVersion: { type: String, default: '1.0.0' },
  maintenanceMessage: { type: String, default: 'التطبيق متوقف حالياً لتحديثات الصيانة' }
});
const SystemSettings = mongoose.model('SystemSettings', systemSettingsSchema);

// ------------------------------------------------------------------------------
// 4. Middlewares
// ------------------------------------------------------------------------------

const appStatusGuard = async (req, res, next) => {
  let settings = await SystemSettings.findOne();
  if (!settings) settings = await SystemSettings.create({});
  
  if (!settings.isAppActive && req.headers['x-admin-key'] !== ADMIN_SECRET_KEY) {
    return res.status(503).json({ success: false, message: settings.maintenanceMessage });
  }
  next();
};

const authGuard = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'غير مصرح بالدخول' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });
    if (user.isBlocked) return res.status(403).json({ success: false, message: 'تم حظر حسابك من قبل الإدارة' });
    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ success: false, message: 'رمز الدخول غير صالح' });
  }
};

const adminGuard = (req, res, next) => {
  const adminKey = req.headers['x-admin-key'];
  if (req.user && req.user.role === 'admin') return next();
  if (adminKey && adminKey === ADMIN_SECRET_KEY) return next();
  
  return res.status(403).json({ success: false, message: 'صلاحيات إدارية مطلوبة لتنفيذ هذا الطلب' });
};

app.use(appStatusGuard);

// ------------------------------------------------------------------------------
// 5. Auth APIs (Secured Role Prevention)
// ------------------------------------------------------------------------------

app.post('/api/auth/send-otp', otpLimiter, async (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ message: 'يرجى إدخال رقم الهاتف' });

  const generatedOtp = crypto.randomInt(100000, 999999).toString();
  const otpExpires = new Date(Date.now() + 5 * 60 * 1000);

  await User.findOneAndUpdate(
    { phone },
    { otp: generatedOtp, otpExpires },
    { upsert: true, new: true }
  );

  console.log(`[WhatsApp Provider]: Sending OTP ${generatedOtp} to ${phone}`);
  res.json({ success: true, message: 'تم إرسال رمز التحقق OTP إلى رقم الواتساب' });
});

app.post('/api/auth/verify-otp', async (req, res) => {
  const { phone, otp, fullName, role, profession, qualification, experience, lng, lat } = req.body;

  const user = await User.findOne({ phone });
  if (!user || user.otp !== otp || user.otpExpires < new Date()) {
    return res.status(400).json({ success: false, message: 'رمز التحقق غير صحيح أو انتهت صلاحيته' });
  }

  if (user.isBlocked) {
    return res.status(403).json({ success: false, message: 'حسابك محظور من استخدام التطبيق' });
  }

  // منع ترقية المستخدم إلى Admin من هذه الواجهة
  let assignedRole = user.role;
  if (!user.fullName) { // تسجيل لأول مرة
    assignedRole = (role === 'admin') ? 'client' : (role || 'client');
  }

  user.fullName = fullName || user.fullName;
  user.role = assignedRole;
  user.profession = profession;
  user.qualification = qualification;
  user.experience = experience;
  if (lng && lat) {
    user.location = { type: 'Point', coordinates: [parseFloat(lng), parseFloat(lat)] };
  }
  user.otp = undefined;
  await user.save();

  const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ success: true, token, user });
});

// ------------------------------------------------------------------------------
// 6. Maintenance & Bidding APIs
// ------------------------------------------------------------------------------

app.post('/api/requests/create', authGuard, async (req, res) => {
  const { serviceCategory, issueType, description, mediaUrls, scheduledDate, address, lng, lat, isUrgent } = req.body;

  const newRequest = await ServiceRequest.create({
    clientId: req.user._id,
    serviceCategory,
    issueType,
    description,
    mediaUrls,
    scheduledDate,
    address,
    isUrgent: isUrgent || false,
    location: { type: 'Point', coordinates: [parseFloat(lng), parseFloat(lat)] }
  });

  const providersInRange = await User.find({
    role: 'provider',
    isBlocked: false,
    location: {
      $near: {
        $geometry: { type: 'Point', coordinates: [parseFloat(lng), parseFloat(lat)] },$maxDistance: 30000 
      }
    }
  });

  res.json({ 
    success: true, 
    message: `تم إرسال الطلب وإشعار ${providersInRange.length} فني في نطاق 30 كم`, 
    request: newRequest 
  });
});

app.post('/api/bids/submit', authGuard, async (req, res) => {
  if (req.user.role !== 'provider') {
    return res.status(403).json({ message: 'الفنيون فقط هم من يمكنهم إرسال عروض الأسعار' });
  }
  const { requestId, price, notes } = req.body;

  const bid = await Bid.create({ requestId, providerId: req.user._id, price, notes });
  await ServiceRequest.findByIdAndUpdate(requestId, { status: 'bidded' });

  res.json({ success: true, message: 'تم إرسال عرض السعر للعميل', bid });
});

app.post('/api/bids/respond', authGuard, async (req, res) => {
  const { bidId, action } = req.body;
  const bid = await Bid.findById(bidId).populate('providerId').populate('requestId');

  if (!bid) return res.status(404).json({ message: 'عرض السعر غير موجود' });

  if (action === 'accept') {
    const agreedPrice = bid.price;
    const commission = agreedPrice * 0.30; 

    const request = await ServiceRequest.findById(bid.requestId._id);
    request.status = 'accepted';
    request.acceptedBidder = bid.providerId._id;
    request.agreedPrice = agreedPrice;
    request.commission = commission;
    await request.save();

    const client = req.user;
    const provider = bid.providerId;

    return res.json({
      success: true,
      action: 'accepted',
      message: 'تم قبول عرض السعر بنجاح وكشف بيانات التواصل',
      noticeForProvider: `تنبيه: سيتم خصم عمولة ${commission} ج.م (30%) لصالح التطبيق فور إتمام الخدمة.`,
      clientData: { fullName: client.fullName, phone: client.phone },
      providerData: { fullName: provider.fullName, phone: provider.phone, profession: provider.profession }
    });
  } else {
    return res.json({
      success: true,
      action: 'rejected',
      message: 'تم رفض عرض السعر ولم يتم كشف بيانات التواصل للطرفين.'
    });
  }
});

// إتمام الطلب والخصم الفعلي للعمولة
app.post('/api/requests/complete', authGuard, async (req, res) => {
  const { requestId } = req.body;
  const request = await ServiceRequest.findById(requestId);

  if (!request || request.status === 'completed') {
    return res.status(400).json({ success: false, message: 'الطلب غير موجود أو اكمل سابقاً' });
  }

  request.status = 'completed';
  await request.save();

  // خصم العمولة من محفظة الفني عند الإتمام الفعلي
  if (request.acceptedBidder && request.commission) {
    await User.findByIdAndUpdate(request.acceptedBidder, { $inc: { walletBalance: -request.commission } });
  }

  res.json({ success: true, message: 'تم تأكيد إتمام الخدمة بنجاح وخصم العمولة المستحقة' });
});

// ------------------------------------------------------------------------------
// 7. Wallet & Payment Proof APIs
// ------------------------------------------------------------------------------

app.get('/api/payments/info', authGuard, async (req, res) => {
  let paymentInfo = await PaymentMethod.findOne();
  if (!paymentInfo) {
    paymentInfo = await PaymentMethod.create({
      vodafoneCashNumber: '01010057274',
      instapayAddress: '01010057274',
      instructions: 'يرجى تحويل العمولة المستحقة على الرقم الموضح ثم رفع صورة الإيصال للتحقق.'
    });
  }
  res.json({ success: true, paymentInfo });
});

app.post('/api/payments/submit-proof', authGuard, upload.single('receiptImage'), async (req, res) => {
  try {
    const { amount, method, transactionRef } = req.body;

    if (!amount || !method) {
      return res.status(400).json({ success: false, message: 'يرجى تحديد المبلغ وطريقة التحويل' });
    }

    if (!req.file) {
      return res.status(400).json({ success: false, message: 'يرجى إرفاق صورة إيصال التحويل' });
    }

    const receiptUrl = `${req.protocol}://${req.get('host')}/uploads/receipts/${req.file.filename}`;

    const transaction = await PaymentTransaction.create({
      providerId: req.user._id,
      amount: parseFloat(amount),
      method,
      transactionRef,
      receiptImage: receiptUrl,
      status: 'pending'
    });

    res.json({
      success: true,
      message: 'تم رفع صورة الإيصال بنجاح وجاري مراجعته من قبل الإدارة لتسوية محفظتك.',
      transaction
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء رفع ملف الإيصال', error: err.message });
  }
});

// ------------------------------------------------------------------------------
// 8. Admin APIs (Owner & Control Panel)
// ------------------------------------------------------------------------------

app.post('/api/admin/payments/approve', authGuard, adminGuard, async (req, res) => {
  const { transactionId } = req.body;
  const transaction = await PaymentTransaction.findById(transactionId);

  if (!transaction || transaction.status !== 'pending') {
    return res.status(400).json({ success: false, message: 'طلب التسديد غير موجود أو تم البت فيه سابقاً' });
  }

  transaction.status = 'approved';
  await transaction.save();

  await User.findByIdAndUpdate(transaction.providerId, { $inc: { walletBalance: transaction.amount } });

  res.json({ success: true, message: 'تم تأكيد استلام المبلغ وتسوية محفظة الفني بنجاح' });
});

app.post('/api/admin/toggle-block', authGuard, adminGuard, async (req, res) => {
  const { userId, isBlocked } = req.body;
  await User.findByIdAndUpdate(userId, { isBlocked });
  res.json({ success: true, message: `تم ${isBlocked ? 'حظر' : 'فك حظر'} المستخدم بنجاح` });
});

app.post('/api/admin/toggle-app-status', authGuard, adminGuard, async (req, res) => {
  const { isAppActive, message } = req.body;
  let settings = await SystemSettings.findOne();
  if (!settings) settings = new SystemSettings();
  
  settings.isAppActive = isAppActive;
  if (message) settings.maintenanceMessage = message;
  await settings.save();

  res.json({ success: true, message: `تم ${isAppActive ? 'تفعيل وتشغيل' : 'إيقاف'} التطبيق بنجاح` });
});

app.get('/api/admin/dashboard-stats', authGuard, adminGuard, async (req, res) => {
  const totalRequests = await ServiceRequest.countDocuments();
  const completedRequests = await ServiceRequest.countDocuments({ status: 'completed' });
  const totalProviders = await User.countDocuments({ role: 'provider' });
  const pendingReceipts = await PaymentTransaction.countDocuments({ status: 'pending' });

  const totalCommission = await ServiceRequest.aggregate([
    { $match: { status: 'completed' } },
    { $group: { _id: null, total: { $sum: '$commission' } } }
  ]);

  res.json({
    totalRequests,
    completedRequests,
    totalProviders,
    pendingReceipts,
    totalRevenueCommission: totalCommission[0]?.total || 0
  });
});

// ------------------------------------------------------------------------------
// 9. Server Start
// ------------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`========================================================`);
  console.log(`Al-Naeemi Maintenance Engine Running Securely on Port ${PORT}`);
  console.log(`Vodafone Cash & InstaPay Receiver: 01010057274`);
  console.log(`========================================================`);
});
