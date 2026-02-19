/*
Example test script to send FCM push using Firebase Admin SDK.
Usage:
  cd server
  node sendPush.js <FCM_TOKEN>

It reads Firebase admin credentials from env vars in server/.env (already present in your repo).
Ensure you have:
  FIREBASE_PROJECT_ID
  FIREBASE_CLIENT_EMAIL
  FIREBASE_PRIVATE_KEY (with literal newlines escaped as \n)

This script sends both notification and data payload so web app can show localized UI.
*/

const admin = require('firebase-admin');
require('dotenv').config();

const projectId = process.env.FIREBASE_PROJECT_ID;
const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
let privateKey = process.env.FIREBASE_PRIVATE_KEY || '';
if (privateKey && privateKey.indexOf('\\n') !== -1) privateKey = privateKey.replace(/\\n/g, '\n');

if (!projectId || !clientEmail || !privateKey) {
  console.error('Missing Firebase admin credentials in environment. Check server/.env');
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.cert({
    projectId,
    clientEmail,
    privateKey
  })
});

const token = process.argv[2];
if (!token) {
  console.error('Usage: node sendPush.js <FCM_TOKEN>');
  process.exit(1);
}

const message = {
  token,
  notification: {
    title: "Feelin' Coffee — Pembaruan Pesanan",
    body: "Pesanan Anda telah diperbarui. Buka aplikasi untuk detail."
  },
  data: {
    type: 'status',
    orderId: 'TEST_ORDER_123',
    orderNumber: 'TEST_ORDER_123',
    status: 'confirmed',
    amountFormatted: 'Rp10.000'
  }
};

admin.messaging().send(message)
  .then((response) => {
    console.log('Successfully sent message:', response);
    process.exit(0);
  })
  .catch((error) => {
    console.error('Error sending message:', error);
    process.exit(1);
  });
