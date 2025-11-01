// Shared auth/session helpers and Firebase initialization for Timon HS Soccer portal
// Uses Firestore-stored users with client-side PBKDF2 password hashing.

// Firebase imports
import { initializeApp } from "https://www.gstatic.com/firebasejs/12.5.0/firebase-app.js";
import { getFirestore, collection, query, where, getDocs, doc, getDoc, setDoc, updateDoc } from "https://www.gstatic.com/firebasejs/12.5.0/firebase-firestore.js";

// ---- Firebase init (single source of truth) ----
export const firebaseConfig = {
	apiKey: "AIzaSyCBYCj-gsiuAZSnRINPrSsxUWjx6IscSwI",
	authDomain: "soccer-footage.firebaseapp.com",
	projectId: "soccer-footage",
	storageBucket: "soccer-footage.firebasestorage.app",
	messagingSenderId: "571193015931",
	appId: "1:571193015931:web:bfb7732e2a40609408acde"
};

export const app = initializeApp(firebaseConfig);
export const db = getFirestore(app);

// ---- Crypto helpers (PBKDF2) ----
function str2ab(str) { return new TextEncoder().encode(str); }
function ab2b64(buf) {
	const bytes = new Uint8Array(buf);
	let binary = "";
	for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
	return btoa(binary);
}
function b642ab(b64) {
	const binary = atob(b64);
	const len = binary.length;
	const bytes = new Uint8Array(len);
	for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
	return bytes.buffer;
}

export async function deriveKey(password, saltB64, iterations = 150000) {
	const salt = b642ab(saltB64);
	const keyMaterial = await crypto.subtle.importKey('raw', str2ab(password), { name: 'PBKDF2' }, false, ['deriveBits']);
	const derivedBits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, keyMaterial, 256);
	return ab2b64(derivedBits);
}

export function randomSaltB64(length = 16) {
	const salt = crypto.getRandomValues(new Uint8Array(length));
	return ab2b64(salt.buffer);
}

// ---- Session helpers ----
const SESSION_KEY = 'timon_currentUser';
export function getSessionUser() {
	try { return JSON.parse(sessionStorage.getItem(SESSION_KEY)); } catch { return null; }
}
export function setSessionUser(userObj) {
	sessionStorage.setItem(SESSION_KEY, JSON.stringify(userObj));
}
export function clearSession() { sessionStorage.removeItem(SESSION_KEY); }

export function attachLogout(target, redirect = '../index.html') {
	let el = target;
	if (typeof target === 'string') el = document.querySelector(target);
	if (!el) return;
	el.addEventListener('click', () => {
		clearSession();
		window.location.href = redirect;
	});
}

// ---- Firestore user helpers ----
export async function getUserDocByEmail(email) {
	const q = query(collection(db, 'users'), where('email', '==', (email || '').toLowerCase()));
	const snap = await getDocs(q);
	return snap.empty ? null : snap.docs[0];
}

export async function getUserDocById(uid) {
	return await getDoc(doc(db, 'users', uid));
}

export async function registerWithEmailPassword(email, password, { isAdmin = false, displayName } = {}) {
	const existing = await getUserDocByEmail(email);
	if (existing) throw new Error('Email already registered');
	const salt = randomSaltB64();
	const iterations = 150000;
	const passwordHash = await deriveKey(password, salt, iterations);
	const usersCol = collection(db, 'users');
	const newDocRef = doc(usersCol);
	const name = displayName || email.split('@')[0];
	await setDoc(newDocRef, {
		email: email.toLowerCase(),
		displayName: name,
		passwordHash,
		salt,
		iterations,
		isAdmin,
		createdAt: new Date(),
		createdDate: new Date().toISOString(),
		lastLogin: new Date()
	});
	const sessionUser = { uid: newDocRef.id, email: email.toLowerCase(), displayName: name, isAdmin };
	setSessionUser(sessionUser);
	return { ref: newDocRef, user: sessionUser };
}

export async function loginWithEmailPassword(email, password) {
	const docSnap = await getUserDocByEmail(email);
	if (!docSnap) throw new Error('User not found');
	const data = docSnap.data();
	const derived = await deriveKey(password, data.salt, data.iterations || 150000);
	if (derived !== data.passwordHash) throw new Error('Invalid email or password');
	const sessionUser = { uid: docSnap.id, email: data.email, displayName: data.displayName || data.email.split('@')[0], isAdmin: !!data.isAdmin };
	setSessionUser(sessionUser);
	await updateDoc(doc(db, 'users', docSnap.id), { lastLogin: new Date() });
	return { user: sessionUser, data };
}

export async function validateSessionAndGetUser({ requireAdmin = false, redirectTo = '../index.html', redirectIfNotAdmin = null } = {}) {
	const sessionUser = getSessionUser();
	if (!sessionUser) {
		if (redirectTo) window.location.href = redirectTo;
		throw new Error('No session');
	}
	const userDocSnap = await getUserDocById(sessionUser.uid);
	if (!userDocSnap.exists()) {
		clearSession();
		if (redirectTo) window.location.href = redirectTo;
		throw new Error('User doc missing');
	}
	const data = userDocSnap.data();
	if (requireAdmin && !data.isAdmin) {
		if (redirectIfNotAdmin) window.location.href = redirectIfNotAdmin; else if (redirectTo) window.location.href = redirectTo;
		throw new Error('Admin required');
	}
	return { user: sessionUser, data };
}

// ---- Admin seed (idempotent) ----
// Seeding removed; admins should be assigned manually by an existing admin.

