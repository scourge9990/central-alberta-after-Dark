# Central Alberta After Dark - Premium Feature Test Checklist

**Platform Focus: 100% Platonic Friendships**  
All tests must verify the platform maintains its platonic nature - no dating, no romantic content, friendship connections only.

---

## Test Environment Setup

### Pre-Test Requirements
- [ ] Two test accounts created (TestUser1, TestUser2)
- [ ] Email verification completed for both accounts
- [ ] Basic profiles completed (photo, bio, interests)
- [ ] Stripe test mode configured
- [ ] Test database/instance ready for fresh installs

### Browser/Device Requirements
- [ ] Desktop browser (Chrome, Firefox, Safari)
- [ ] Mobile responsive testing (iOS Safari, Android Chrome)
- [ ] Incognito/Private browsing for clean state tests
- [ ] Multiple browser sessions for concurrent testing

---

## 1. FREE USER BASELINE TESTS

### 1.1 Homepage & Navigation (Free User)
- [ ] **Landing Page Load**
  - [ ] Homepage displays without errors
  - [ ] Header with "Central Alberta After Dark" branding visible
  - [ ] Alberta flag image renders correctly
  - [ ] "All Night Owls" default filter is selected/highlighted
  
- [ ] **Right Sidebar Categories Visible**
  - [ ] All Night Owls - visible
  - [ ] Online Now - visible
  - [ ] Night Shift Workers - visible
  - [ ] Fishing Buddies - visible
  - [ ] Fur Parents - visible
  - [ ] Road Trip Companions - visible
  - [ ] Hit The Pub - visible
  - [ ] Late Night Gamers - visible
  - [ ] Stargazing Friends - visible
  - [ ] Graveyard Shift Fitness Buddies - visible
  - [ ] Late Night Book Club - visible

- [ ] **Category Filtering Works**
  - [ ] Clicking "Online Now" filters profiles correctly
  - [ ] Clicking "Night Shift Workers" filters correctly
  - [ ] Clicking "Fishing Buddies" filters correctly
  - [ ] Active filter is visually highlighted (yellow background)
  - [ ] "All Night Owls" shows complete user pool

### 1.2 Registration & Login (Free User)
- [ ] **Registration Flow**
  - [ ] Can register with valid email/password
  - [ ] Password strength requirements enforced
  - [ ] Email verification link sent
  - [ ] Can verify email and activate account
  - [ ] Error messages display for invalid inputs
  
- [ ] **Login Flow**
  - [ ] Can login with verified credentials
  - [ ] "Remember me" functionality works
  - [ ] Password reset via email works
  - [ ] Error for invalid credentials

### 1.3 Profile Management (Free User)
- [ ] **Profile Creation**
  - [ ] Can add profile photo (up to 5MB)
  - [ ] Can add bio (character limit enforced)
  - [ ] Can set location (Central Alberta area)
  - [ ] Can select interests/categories
  - [ ] Can set work schedule (night shift, etc.)
  
- [ ] **Profile Viewing**
  - [ ] Can view own profile
  - [ ] Can edit profile information
  - [ ] Can delete/change profile photo
  - [ ] Changes save correctly

### 1.4 Browsing & Discovery (Free User)
- [ ] **Profile Cards Display**
  - [ ] Profile photos render correctly
  - [ ] Username and age visible
  - [ ] Location displayed
  - [ ] Online status indicator works
  - [ ] Category badges display
  
- [ ] **Interactions Available to Free Users**
  - [ ] Can "Like" other profiles
  - [ ] Can view profiles without liking
  - [ ] Can use all category filters

### 1.5 Advertisements (Free User)
- [ ] **Ads Display**
  - [ ] Sidebar ads visible
  - [ ] Ad images load correctly
  - [ ] Clickable ads open external links
  - [ ] "Advertise Here" placeholder visible

### 1.6 Chat/Ticker (Free User)
- [ ] **Public Chat Ticker**
  - [ ] Can view chat ticker feed
  - [ ] Can post public messages
  - [ ] Messages appear in real-time
  - [ ] Character limit enforced (300 chars)

---

## 2. PREMIUM SUBSCRIPTION FLOW TESTS

### 2.1 Upgrade Prompt Visibility
- [ ] **Free User Premium Prompts**
  - [ ] Premium upgrade card visible in left sidebar
  - [ ] "Night Owl Premium" title and price ($19.99/mo) visible
  - [ ] Premium benefits listed:
    - [ ] See who viewed your profile
    - [ ] See who liked you
    - [ ] Unlimited messages
    - [ ] Priority placement & boost
    - [ ] Remove all ads

### 2.2 Stripe Checkout Flow
- [ ] **Checkout Initiation**
  - [ ] Click "Go Premium" opens checkout modal/page
  - [ ] Stripe payment form loads correctly
  - [ ] Test card options available (4242 4242 4242 4242)
  
- [ ] **Payment Processing**
  - [ ] Can enter valid test card
  - [ ] Payment processes successfully
  - [ ] Redirect to success page works
  - [ ] Confirmation email received
  
- [ ] **Failed Payment Handling**
  - [ ] Declined card shows appropriate error
  - [ ] Network error handled gracefully
  - [ ] User remains on checkout page

### 2.3 Subscription Confirmation
- [ ] **Success Page**
  - [ ] "Welcome to Night Owl Premium!" message
  - [ ] Subscription details displayed
  - [ ] Link to return to homepage
  - [ ] Email confirmation sent
  
- [ ] **Database Update**
  - [ ] User `is_premium` field set to `true`
  - [ ] Subscription date recorded
  - [ ] Subscription expiry calculated

---

## 3. PREMIUM FEATURE ACTIVATION TESTS

### 3.1 Profile Views Feature (⭐ PREMIUM)
**Expected: Free users CANNOT see who viewed their profile**

- [ ] **Free User View**
  - [ ] Profile views section NOT accessible
  - [ ] Clicking profile views shows upgrade prompt
  - [ ] API returns 403 with `premium_required: true`
  - [ ] Toast/popup prompts upgrade to premium

- [ ] **Premium User View**
  - [ ] "Profile Views" section visible in navigation/menu
  - [ ] Can access full profile views list
  - [ ] Viewers' usernames displayed
  - [ ] Viewers' locations shown
  - [ ] Viewers' ages shown
  - [ ] Timestamp of view displayed
  - [ ] Sort by most recent works
  - [ ] Limit of 50 viewers enforced

- [ ] **Edge Cases**
  - [ ] New user with no profile views shows empty state
  - [ ] View count updates when new person views
  - [ ] Same viewer counted once per day
  - [ ] Logout/login preserves view data

### 3.2 "Who Liked Me" Feature (⭐ PREMIUM)
**Expected: Free users CAN see likes received, but cannot see WHO liked them**

- [ ] **Free User View**
  - [ ] Can see they received a "like" (notification/badge)
  - [ ] CANNOT see full list of users who liked them
  - [ ] Upgrade prompt shown when clicking likes
  - [ ] API returns limited data for free users

- [ ] **Premium User View**
  - [ ] Full list of users who liked them accessible
  - [ ] Each liker's profile photo displayed
  - [ ] Username visible
  - [ ] Location shown
  - [ ] Bio preview available
  - [ ] Can click to view full profile
  - [ ] Can initiate chat from likes list

- [ ] **Edge Cases**
  - [ ] New user with no likes shows encouraging message
  - [ ] Like notification appears in real-time
  - [ ] Mutual likes highlighted differently
  - [ ] Can unlike/remove someone from list

### 3.3 Messaging Feature (⭐ PREMIUM)
**Expected: Free users CANNOT send/receive private messages**

- [ ] **Free User View**
  - [ ] Message button NOT visible on profiles
  - [ ] Clicking any message trigger shows upgrade prompt
  - [ ] Accessing `/messages` route shows upgrade prompt
  - [ ] API returns 403 for message attempts
  - [ ] Toast: "Night Owl Premium required to send messages"

- [ ] **Premium User View**
  - [ ] "Messages" in navigation/header
  - [ ] Can access full messaging interface
  - [ ] Conversations list displays
  - [ ] Can open conversation thread
  - [ ] Can send text messages
  - [ ] Messages delivered in real-time (or near real-time)
  - [ ] Unread message count badge visible

- [ ] **Messaging Limits (Premium)**
  - [ ] Messages ARE unlimited (no daily cap)
  - [ ] Character limit: 1000 chars enforced
  - [ ] Empty message rejected
  - [ ] Rate limiting (if any) is generous

- [ ] **Edge Cases**
  - [ ] Long messages wrap correctly
  - [ ] Special characters supported
  - [ ] Emoji support works
  - [ ] Deleted messages handled gracefully
  - [ ] Block user functionality works

### 3.4 Search Priority & Boost (⭐ PREMIUM)
**Expected: Premium users appear higher in browse lists**

- [ ] **Free User Browse Position**
  - [ ] Standard ordering algorithm applied
  - [ ] Recent activity factors into ranking
  - [ ] Premium users appear ahead

- [ ] **Premium User Browse Position**
  - [ ] Appears in "Priority" or "Featured" section
  - [ ] Badge/indicator shows "Night Owl Premium"
  - [ ] Visually distinguished in profile cards
  - [ ] More profile impressions received

- [ ] **Edge Cases**
  - [ ] New premium users added to priority pool
  - [ ] Expired premium returns to standard pool
  - [ ] Boost is daily/weekly refresh
  - [ ] Manual boost option (if implemented)

### 3.5 Ad Removal (⭐ PREMIUM)
**Expected: Premium users see NO advertisements**

- [ ] **Free User Ad Display**
  - [ ] Left sidebar ads visible
  - [ ] "Advertise Here" cards displayed
  - [ ] External ads render correctly
  - [ ] Ads do not interfere with content

- [ ] **Premium User Ad Display**
  - [ ] All ads hidden/removed
  - [ ] Left sidebar shows premium benefits only
  - [ ] Clean, ad-free browsing experience
  - [ ] Page loads faster (no ad scripts)

- [ ] **Edge Cases**
  - [ ] Ad-free persists across page navigation
  - [ ] Mobile experience ad-free
  - [ ] Refresh maintains ad-free state
  - [ ] Logout/login preserves ad-free for premium

### 3.6 Category Filtering (⭐ PREMIUM)
**Expected: All categories visible to ALL users (free & premium)**

- [ ] **Category Visibility (Both User Types)**
  - [ ] All Night Owls - visible to everyone
  - [ ] Online Now - visible to everyone
  - [ ] Night Shift Workers - visible to everyone
  - [ ] Fishing Buddies - visible to everyone
  - [ ] Fur Parents - visible to everyone
  - [ ] Road Trip Companions - visible to everyone
  - [ ] Hit The Pub - visible to everyone
  - [ ] Late Night Gamers - visible to everyone
  - [ ] Stargazing Friends - visible to everyone
  - [ ] Graveyard Shift Fitness Buddies - visible to everyone
  - [ ] Late Night Book Club - visible to everyone

- [ ] **Category Filtering Accuracy**
  - [ ] Each filter shows only matching profiles
  - [ ] Profile's selected interests match category
  - [ ] Multiple interests = appears in multiple categories
  - [ ] Empty category shows "No night owls found" message

- [ ] **Edge Cases**
  - [ ] Profile with no interests appears in "All Night Owls" only
  - [ ] Profile can belong to multiple categories
  - [ ] Category counts update when profiles change

---

## 4. PLATONIC NATURE ENFORCEMENT TESTS

### 4.1 Content Moderation
**Critical: All features must enforce platonic friendships only**

- [ ] **Registration/Profile**
  - [ ] Terms explicitly state "platonic friendships only"
  - [ ] Bio prompts encourage friendship activities
  - [ ] No "relationship status" options
  - [ ] No gender preference filters for dating

- [ ] **Profile Content**
  - [ ] Romantic language flagged/blocked
  - [ ] Explicit content blocked from uploads
  - [ ] Report button available on profiles
  - [ ] Report categories include inappropriate behavior

- [ ] **Messaging Content**
  - [ ] Romantic phrase detection active
  - [ ] Blocked phrases list enforced:
    - [ ] "date", "dating", "hook up"
    - [ ] "boyfriend", "girlfriend"
    - [ ] Explicit requests blocked
  - [ ] Warning message on flagged content
  - [ ] Repeat offenders suspended

- [ ] **Public Chat Ticker**
  - [ ] Same content filters applied
  - [ ] "Looking for love" messages rejected
  - [ ] Platonic activity suggestions encouraged

### 4.2 User Reporting
- [ ] **Report Mechanism**
  - [ ] "Report" button visible on profiles
  - [ ] Report modal/flow accessible
  - [ ] Multiple report reasons available:
    - [ ] Inappropriate content
    - [ ] Harassment
    - [ ] Romance/dating attempt
    - [ ] Fake profile
    - [ ] Other
  - [ ] Optional details text field
  - [ ] Submit confirmation shown

- [ ] **Admin Review (Manual Check)**
  - [ ] Reports logged in database
  - [ ] Reporter identity recorded
  - [ ] Reported profile flagged
  - [ ] Admin notification triggered

### 4.3 Community Guidelines
- [ ] **Guidelines Display**
  - [ ] Terms of Service page accessible
  - [ ] Privacy Policy page accessible
  - [ ] Community guidelines in footer
  - [ ] Age verification (18+) enforced

- [ ] **Guidelines Content**
  - [ ] Explicit platonic focus stated
  - [ ] Prohibited behaviors listed
  - [ ] Reporting procedures documented
  - [ ] Enforcement policy explained

---

## 5. SECURITY & PERFORMANCE TESTS

### 5.1 Authentication Security
- [ ] **Session Management**
  - [ ] Secure cookies configured (HTTPS in production)
  - [ ] Session expires after 7 days
  - [ ] Logout invalidates session
  - [ ] CSRF tokens work correctly
  
- [ ] **Password Security**
  - [ ] Passwords hashed with bcrypt
  - [ ] Minimum password length enforced
  - [ ] Password change requires current password

### 5.2 API Security
- [ ] **Rate Limiting**
  - [ ] Login: 200 attempts/15 minutes
  - [ ] Registration: 5 attempts/hour
  - [ ] General API: 500 requests/15 minutes
  - [ ] Rate limit errors display user-friendly messages

- [ ] **Premium Feature Protection**
  - [ ] CSRF protection on all POST requests
  - [ ] Premium features check session server-side
  - [ ] Direct API access blocked without auth

### 5.3 Data Validation
- [ ] **Input Sanitization**
  - [ ] XSS protection on all inputs
  - [ ] SQL injection prevention
  - [ ] File upload type validation
  - [ ] Character limits enforced server-side

### 5.4 Performance
- [ ] **Page Load Times**
  - [ ] Homepage loads < 3 seconds
  - [ ] Profile images lazy-load
  - [ ] Category filters respond instantly
  
- [ ] **API Response Times**
  - [ ] Profile list < 500ms
  - [ ] Like action < 200ms
  - [ ] Message send < 300ms

---

## 6. MOBILE RESPONSIVE TESTS

### 6.1 Layout Adaptations
- [ ] **Header**
  - [ ] Responsive scaling on mobile
  - [ ] Logo/title readable on small screens
  - [ ] Auth buttons accessible

- [ ] **Sidebar**
  - [ ] Categories scroll horizontally or collapse
  - [ ] Touch-friendly tap targets (min 44px)
  - [ ] Sticky positioning works on mobile

- [ ] **Profile Cards**
  - [ ] Stack vertically on mobile
  - [ ] Images scale appropriately
  - [ ] Text remains readable

### 6.2 Mobile Interactions
- [ ] **Touch Gestures**
  - [ ] Like button works on touch
  - [ ] Filter selection works
  - [ ] Scroll is smooth

- [ ] **Forms**
  - [ ] Keyboard doesn't cover inputs
  - [ ] Submit buttons accessible
  - [ ] Validation messages visible

---

## 7. CROSS-BROWSER TESTS

### 7.1 Browser Compatibility
- [ ] **Chrome (Latest)**
  - [ ] All features functional
  - [ ] No console errors
  
- [ ] **Firefox (Latest)**
  - [ ] All features functional
  - [ ] No console errors
  
- [ ] **Safari (Latest)**
  - [ ] All features functional
  - [ ] No console errors
  
- [ ] **Edge (Latest)**
  - [ ] All features functional
  - [ ] No console errors

### 7.2 Progressive Web App
- [ ] **PWA Features**
  - [ ] Service worker registers
  - [ ] App installable
  - [ ] Offline page displays gracefully

---

## 8. SUBSCRIPTION MANAGEMENT TESTS

### 8.1 Subscription Status
- [ ] **Account Page**
  - [ ] Subscription status displayed
  - [ ] "Active" badge for premium
  - [ ] Renewal date shown

### 8.2 Subscription Cancellation
- [ ] **Cancel Flow**
  - [ ] Cancel button accessible
  - [ ] Cancellation confirmation shown
  - [ ] Access continues until period end
  - [ ] Confirmation email sent

### 8.3 Subscription Resumption
- [ ] **Reactivation**
  - [ ] Can resubscribe after cancellation
  - [ ] Previous data preserved
  - [ ] Immediate access restored

### 8.4 Payment Failures
- [ ] **Failed Payment Handling**
  - [ ] Grace period provided (e.g., 7 days)
  - [ ] Email notification sent
  - [ ] Access maintained during grace period
  - [ ] Account suspended after grace period

---

## 9. EDGE CASE & ERROR SCENARIOS

### 9.1 Network Issues
- [ ] **Offline Handling**
  - [ ] "No connection" message shown
  - [ ] Retry button available
  - [ ] Partial data preserved

### 9.2 Data Corruption
- [ ] **Recovery Scenarios**
  - [ ] Invalid profile data handled
  - [ ] Missing images show placeholder
  - [ ] Database errors logged

### 9.3 Concurrent Sessions
- [ ] **Multi-Device**
  - [ ] Can be logged in on multiple devices
  - [ ] Session invalidation on password change
  - [ ] Consistent state across devices

### 9.4 Timezone Handling
- [ ] **Time Display**
  - [ ] Profile view times in local timezone
  - [ ] "Online Now" accurate per timezone
  - [ ] Chat timestamps correct

---

## 10. POST-DEPLOYMENT VERIFICATION

### 10.1 Production Smoke Tests
- [ ] **Live Environment**
  - [ ] Homepage loads correctly
  - [ ] User registration works
  - [ ] Payment processing works
  - [ ] Premium features activate

### 10.2 Monitoring Setup
- [ ] **Health Checks**
  - [ ] Server health endpoint configured
  - [ ] Uptime monitoring active
  - [ ] Error alerting configured

---

## TEST EXECUTION TRACKING

### Sign-Off Checklist

| Test Category | Tester Name | Date | Pass/Fail | Notes |
|---------------|-------------|------|-----------|-------|
| Free User Baseline | | | | |
| Premium Subscription | | | | |
| Profile Views | | | | |
| Who Liked Me | | | | |
| Messaging | | | | |
| Search Priority | | | | |
| Ad Removal | | | | |
| Category Filtering | | | | |
| Platonic Enforcement | | | | |
| Security | | | | |
| Mobile Responsive | | | | |
| Cross-Browser | | | | |
| Subscription Mgmt | | | | |

---

## KNOWN LIMITATIONS / FUTURE IMPROVEMENTS

1. [ ] Add real-time messaging via WebSockets
2. [ ] Implement push notifications
3. [ ] Add location-based filtering
4. [ ] Implement profile verification badges
5. [ ] Add "Night Owl of the Week" feature
6. [ ] Create mobile app (iOS/Android)

---

*Last Updated: June 2026*
*Test Suite Version: 1.0*
