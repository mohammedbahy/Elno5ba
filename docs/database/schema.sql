-- Elno5ba Relational Schema (DDL)
-- This optional SQL representation mirrors the Firestore collections so you can
-- generate an ERD / relational diagram quickly. Adjust data types to match the
-- SQL engine you plan to use (PostgreSQL syntax by default).

CREATE TABLE users (
    user_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    auth_uid           VARCHAR(64)  NOT NULL UNIQUE, -- Firebase UID
    full_name          VARCHAR(150) NOT NULL,
    email              VARCHAR(255) NOT NULL UNIQUE,
    phone              VARCHAR(32),
    bio                TEXT,
    photo_url          TEXT,
    preferred_language CHAR(5)      NOT NULL DEFAULT 'en',
    country_code       CHAR(2),
    is_active          BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE user_roles (
    user_id    UUID REFERENCES users(user_id) ON DELETE CASCADE,
    role       VARCHAR(32) NOT NULL CHECK (role IN ('student', 'instructor', 'admin')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, role)
);

CREATE TABLE instructor_profiles (
    instructor_id     UUID PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
    headline          VARCHAR(255),
    about             TEXT,
    years_of_experience SMALLINT CHECK (years_of_experience BETWEEN 0 AND 70),
    facebook_url      TEXT,
    instagram_url     TEXT,
    youtube_url       TEXT,
    website_url       TEXT,
    total_courses     INTEGER NOT NULL DEFAULT 0,
    total_students    INTEGER NOT NULL DEFAULT 0,
    total_earnings    NUMERIC(12, 2) NOT NULL DEFAULT 0,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE courses (
    course_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    instructor_id     UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    title             VARCHAR(200) NOT NULL,
    slug              VARCHAR(220) NOT NULL UNIQUE,
    category          VARCHAR(120) NOT NULL,
    language          CHAR(5)      NOT NULL DEFAULT 'en',
    level             VARCHAR(32)  NOT NULL DEFAULT 'beginner',
    tags              TEXT[]       DEFAULT '{}',
    price_cents       INTEGER      NOT NULL CHECK (price_cents >= 0),
    currency          CHAR(3)      NOT NULL DEFAULT 'EGP',
    description       TEXT,
    what_you_will_learn TEXT[],
    requirements      TEXT[],
    cover_image_url   TEXT,
    intro_video_url   TEXT,
    rating            NUMERIC(3, 2) NOT NULL DEFAULT 0,
    total_ratings     INTEGER       NOT NULL DEFAULT 0,
    enrolled_students INTEGER       NOT NULL DEFAULT 0,
    is_published      BOOLEAN       NOT NULL DEFAULT FALSE,
    created_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE TABLE course_modules (
    module_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    course_id   UUID NOT NULL REFERENCES courses(course_id) ON DELETE CASCADE,
    title       VARCHAR(200) NOT NULL,
    summary     TEXT,
    display_order INTEGER NOT NULL DEFAULT 0,
    UNIQUE (course_id, display_order)
);

CREATE TABLE course_lessons (
    lesson_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    module_id     UUID NOT NULL REFERENCES course_modules(module_id) ON DELETE CASCADE,
    title         VARCHAR(200) NOT NULL,
    content_type  VARCHAR(32)  NOT NULL DEFAULT 'video',
    content_url   TEXT         NOT NULL,
    duration_secs INTEGER,
    is_preview    BOOLEAN      NOT NULL DEFAULT FALSE,
    resources_url TEXT,
    transcript    TEXT,
    display_order INTEGER NOT NULL DEFAULT 0,
    UNIQUE (module_id, display_order)
);

CREATE TABLE payments (
    payment_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    course_id     UUID NOT NULL REFERENCES courses(course_id) ON DELETE CASCADE,
    amount_cents  INTEGER NOT NULL CHECK (amount_cents >= 0),
    currency      CHAR(3) NOT NULL DEFAULT 'EGP',
    method        VARCHAR(32) NOT NULL, -- visa / paypal / wallet / ...
    status        VARCHAR(32) NOT NULL CHECK (status IN ('pending', 'succeeded', 'failed', 'refunded')),
    transaction_ref VARCHAR(100) NOT NULL,
    receipt_url   TEXT,
    processed_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (transaction_ref)
);

CREATE TABLE enrollments (
    enrollment_id  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    course_id      UUID NOT NULL REFERENCES courses(course_id) ON DELETE CASCADE,
    payment_id     UUID REFERENCES payments(payment_id) ON DELETE SET NULL,
    enrolled_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_accessed_at TIMESTAMPTZ,
    progress       NUMERIC(4, 3) NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 1),
    completed      BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (user_id, course_id)
);

CREATE TABLE lesson_progress (
    enrollment_id UUID NOT NULL REFERENCES enrollments(enrollment_id) ON DELETE CASCADE,
    lesson_id     UUID NOT NULL REFERENCES course_lessons(lesson_id) ON DELETE CASCADE,
    progress      NUMERIC(4, 3) NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 1),
    last_watched_at TIMESTAMPTZ,
    PRIMARY KEY (enrollment_id, lesson_id)
);

CREATE TABLE favorites (
    favorite_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    course_id   UUID NOT NULL REFERENCES courses(course_id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, course_id)
);

CREATE TABLE reviews (
    review_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    course_id   UUID NOT NULL REFERENCES courses(course_id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    rating      NUMERIC(2, 1) NOT NULL CHECK (rating BETWEEN 1 AND 5),
    comment     TEXT,
    likes_count INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (course_id, user_id)
);

CREATE TABLE notifications (
    notification_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    title           VARCHAR(160) NOT NULL,
    body            TEXT NOT NULL,
    action_type     VARCHAR(50),        -- e.g. enrollment_success
    action_target   UUID,
    is_read         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Helpful indexes for common lookups
CREATE INDEX idx_courses_instructor ON courses (instructor_id, created_at DESC);
CREATE INDEX idx_courses_category   ON courses (category, is_published);
CREATE INDEX idx_enrollments_user   ON enrollments (user_id);
CREATE INDEX idx_enrollments_course ON enrollments (course_id);
CREATE INDEX idx_payments_user      ON payments (user_id, created_at DESC);
CREATE INDEX idx_reviews_course     ON reviews (course_id, created_at DESC);
CREATE INDEX idx_favorites_user     ON favorites (user_id);

