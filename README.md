# Elno5ba - Educational Platform 📚

<div dir="rtl">

# النخبة - منصة تعليمية 📚

</div>

A modern educational platform built with Jetpack Compose and Firebase, designed to provide an integrated learning experience for students and instructors.

<div dir="rtl">

منصة تعليمية حديثة مبنية باستخدام Jetpack Compose و Firebase، مصممة لتوفير تجربة تعليمية متكاملة للطلاب والمعلمين.

</div>

## Features | المميزات ✨

### For Students | للطلاب
- 📖 Browse and discover courses
- 🔐 Enroll in courses using enrollment codes
- ⭐ Rate and review courses
- ❤️ Save favorite courses
- 📱 User profile management
- 🌐 Multi-language support (Arabic/English)

<div dir="rtl">

- 📖 تصفح واكتشف الكورسات
- 🔐 الاشتراك في الكورسات باستخدام أكواد التسجيل
- ⭐ تقييم ومراجعة الكورسات
- ❤️ حفظ الكورسات المفضلة
- 📱 إدارة الملف الشخصي
- 🌐 دعم متعدد اللغات (العربية/الإنجليزية)

</div>

### For Instructors | للمعلمين
- 🎓 Create and manage courses
- 📹 Upload course videos
- 🔑 Generate enrollment codes for students
- 📊 View enrolled students
- 🎯 Direct access to own courses without enrollment codes

<div dir="rtl">

- 🎓 إنشاء وإدارة الكورسات
- 📹 رفع فيديوهات الكورسات
- 🔑 إنشاء أكواد تسجيل للطلاب
- 📊 عرض الطلاب المسجلين
- 🎯 الوصول المباشر لكورساتك بدون أكواد

</div>

## Tech Stack | التقنيات المستخدمة 🛠️

- **Language**: Kotlin
- **UI Framework**: Jetpack Compose
- **Architecture**: MVVM (Model-View-ViewModel)
- **Backend**: Firebase
  - Firebase Authentication (Email/Password + Google Sign In)
  - Cloud Firestore (Database)
  - Firebase Storage (File Storage)
- **Dependencies**:
  - Material Design 3
  - Navigation Compose
  - Coil (Image Loading)
  - ExoPlayer (Video Playback)
  - Coroutines & Flow
  - ViewModel & LiveData

## Project Structure | هيكل المشروع 📁

```
app/src/main/java/com/bahy/elno5ba/
├── data/
│   ├── model/          # Data models
│   └── repository/     # Data repositories
├── ui/
│   ├── screens/        # App screens
│   ├── components/     # Reusable components
│   ├── viewmodel/      # ViewModels
│   └── utils/          # UI utilities
└── utils/              # General utilities
```

## Prerequisites | المتطلبات 📋

- Android Studio Hedgehog (2023.1.1) or later
- JDK 11 or higher
- Android SDK 29 (Android 10) or higher
- Firebase project with:
  - Authentication enabled
  - Firestore Database configured
  - Storage configured
  - `google-services.json` file added to `app/` directory

## Setup Instructions | تعليمات الإعداد 🔧

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/Elno5ba.git
cd Elno5ba
```

### 2. Firebase Setup

1. Create a Firebase project at [Firebase Console](https://console.firebase.google.com/)
2. Add an Android app to your Firebase project
3. Download `google-services.json` and place it in `app/` directory
4. Enable the following Firebase services:
   - **Authentication**: Email/Password and Google Sign-In
   - **Cloud Firestore**: Create database in production mode
   - **Storage**: Create storage bucket

5. Configure Firestore Security Rules (see `firestore.rules`)

### 3. Google Sign-In Setup

1. In Firebase Console, go to Authentication > Sign-in method
2. Enable Google Sign-In
3. Add your app's SHA-1 fingerprint:
   ```bash
   # For debug keystore
   keytool -list -v -keystore ~/.android/debug.keystore -alias androiddebugkey -storepass android -keypass android
   ```
4. Copy the SHA-1 fingerprint and add it to Firebase Console

### 4. Build and Run

1. Open the project in Android Studio
2. Sync Gradle files
3. Run the app on an emulator or physical device

## Firestore Collections | مجموعات Firestore 📊

- **users**: User basic information (unencrypted for admin access)
- **userProfiles**: Encrypted user profile data
- **userRoles**: User roles (student/instructor)
- **courses**: Course information
- **enrollments**: Student course enrollments
- **enrollmentCodes**: Course enrollment codes
- **reviews**: Course reviews and ratings
- **favorites**: User favorite courses

## User Roles | أدوار المستخدمين 👥

### Student | طالب
- Default role for new users
- Can enroll in courses using codes
- Can rate and review courses
- Can save favorite courses

### Instructor | معلم
- Can create and manage courses
- Can upload course videos
- Can generate enrollment codes
- Has direct access to own courses (no enrollment code needed)
- Role can be changed by admin in Firebase Console

## Admin Features | ميزات الإدارة 🔐

Admins can manage user roles directly from Firebase Console:

1. Go to Firestore Database
2. Navigate to `users` collection to find user by name/email
3. Get the user's `userId` (document ID)
4. Navigate to `userRoles` collection
5. Update the `role` field to `"instructor"` or `"student"`

## Screenshots | لقطات الشاشة 📸

*(Add screenshots of your app here)*

## Contributing | المساهمة 🤝

Contributions are welcome! Please feel free to submit a Pull Request.

<div dir="rtl">

المساهمات مرحب بها! يرجى إرسال Pull Request.

</div>

## License | الترخيص 📄

This project is licensed under the MIT License - see the LICENSE file for details.

<div dir="rtl">

هذا المشروع مرخص تحت رخصة MIT - راجع ملف LICENSE للتفاصيل.

</div>

## Contact | التواصل 📧

For questions or support, please open an issue on GitHub.

<div dir="rtl">

للأسئلة أو الدعم، يرجى فتح issue على GitHub.

</div>
