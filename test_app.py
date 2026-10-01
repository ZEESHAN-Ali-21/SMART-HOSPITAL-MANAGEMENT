import unittest
from fastapi.testclient import TestClient
import main
from main import SessionLocal, User, Patient, Doctor, Nurse, hash_password, verify_password


class SmartHospitalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app, follow_redirects=False)
        db = SessionLocal()
        main.ensure_demo_accounts(db)
        db.close()

    def test_01_admin_login_redirects_to_admin_dashboard(self):
        response = self.client.post('/login', data={'username': 'admin', 'password': 'admin123'})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers['location'], '/admin-dashboard')

    def test_02_admin_login_portal_route(self):
        response = self.client.post('/admin-login', data={'username': 'admin', 'password': 'admin123'})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers['location'], '/admin-dashboard')

    def test_03_doctor_redirects_to_doctor_dashboard(self):
        response = self.client.post('/login', data={'username': 'dr_meera', 'password': 'doctor123'})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers['location'], '/doctor-dashboard')

    def test_04_patient_redirects_to_patient_dashboard(self):
        response = self.client.post('/login', data={'username': 'aarav_pat', 'password': 'patient123'})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers['location'], '/patient-dashboard')

    def test_05_nurse_redirects_to_nurse_dashboard(self):
        response = self.client.post('/login', data={'username': 'nurse_priya', 'password': 'nurse123'})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers['location'], '/nurse-dashboard')

    def test_06_invalid_credentials_returns_error(self):
        response = self.client.post('/login', data={'username': 'admin', 'password': 'wrongpassword'})
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid username or password", response.text)

    def test_07_rbac_doctor_cannot_access_admin_dashboard(self):
        login_res = self.client.post('/login', data={'username': 'dr_meera', 'password': 'doctor123'})
        cookies = login_res.cookies
        response = self.client.get('/admin-dashboard', cookies=cookies)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers['location'], '/access-denied')

    def test_08_rbac_patient_cannot_access_admin_dashboard(self):
        login_res = self.client.post('/login', data={'username': 'aarav_pat', 'password': 'patient123'})
        cookies = login_res.cookies
        response = self.client.get('/admin-dashboard', cookies=cookies)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers['location'], '/access-denied')

    def test_09_create_patient_with_temporary_password_and_mandatory_rotation(self):
        test_username = "test_pat_auto"
        # Clean up if exists
        db = SessionLocal()
        old_u = db.query(User).filter(User.username == test_username).first()
        if old_u:
            db.query(Patient).filter(Patient.user_id == old_u.id).delete()
            db.delete(old_u)
            db.commit()
        db.close()

        # Admin creates patient
        patient_payload = {
            "name": "Auto Test Patient",
            "age": 28,
            "gender": "Female",
            "phone": "+91 99999 88888",
            "address": "45 Park Lane, Delhi",
            "hospital_name": "Smart Hospital Central",
            "disease": "Asthma",
            "ward": "General",
            "username": test_username,
            "temporary_password": "TempPass@123"
        }
        admin_login = self.client.post('/login', data={'username': 'admin', 'password': 'admin123'})
        cookies = admin_login.cookies
        create_res = self.client.post('/api/patients', json=patient_payload, cookies=cookies)
        self.assertEqual(create_res.status_code, 201)
        data = create_res.json()
        self.assertIn("patient_id", data)

        # Patient logs in with temporary password
        login_res = self.client.post('/login', data={'username': test_username, 'password': 'TempPass@123'})
        self.assertEqual(login_res.status_code, 303)
        # MUST redirect to /change-password!
        self.assertEqual(login_res.headers['location'], '/change-password')

        # Patient changes temporary password
        cookies = login_res.cookies
        change_res = self.client.post(
            '/change-password',
            data={
                'current_password': 'TempPass@123',
                'new_password': 'NewSecurePass@456',
                'confirm_password': 'NewSecurePass@456'
            },
            cookies=cookies
        )
        self.assertEqual(change_res.status_code, 303)
        self.assertEqual(change_res.headers['location'], '/patient-dashboard')

        # Verify password is now securely hashed in DB and must_change_password is 0
        db = SessionLocal()
        u = db.query(User).filter(User.username == test_username).first()
        self.assertEqual(u.must_change_password, 0)
        self.assertTrue(u.password.startswith("pbkdf2_sha256$"))
        self.assertTrue(verify_password("NewSecurePass@456", u.password))

        # Clean up
        db.query(Patient).filter(Patient.user_id == u.id).delete()
        db.delete(u)
        db.commit()
        db.close()

    def test_10_doctor_crud_operations(self):
        doc_username = "dr_rajesh_test"
        db = SessionLocal()
        old_u = db.query(User).filter(User.username == doc_username).first()
        if old_u:
            db.query(Doctor).filter(Doctor.user_id == old_u.id).delete()
            db.delete(old_u)
            db.commit()
        db.close()

        # Create doctor
        admin_login = self.client.post('/login', data={'username': 'admin', 'password': 'admin123'})
        cookies = admin_login.cookies
        create_res = self.client.post('/api/doctors', json={
            "name": "Dr. Rajesh Gupta",
            "age": 48,
            "specialization": "Neurology",
            "phone": "+91 91111 22222",
            "address": "12 Medical Enclave",
            "hospital_name": "Smart Hospital Central",
            "department": "Neurology",
            "shift": "Morning",
            "username": doc_username,
            "temporary_password": "DocTemp@123"
        }, cookies=cookies)
        self.assertEqual(create_res.status_code, 201)
        doc_id = create_res.json()["doctor_id"]

        # Read doctor
        get_res = self.client.get(f'/api/doctors/{doc_id}', cookies=cookies)
        self.assertEqual(get_res.status_code, 200)
        self.assertEqual(get_res.json()["name"], "Dr. Rajesh Gupta")
        self.assertEqual(get_res.json()["username"], doc_username)

        # Update doctor
        update_res = self.client.put(f'/api/doctors/{doc_id}', json={
            "name": "Dr. Rajesh K. Gupta",
            "specialization": "Neurosurgery",
            "phone": "+91 91111 33333",
            "address": "12 Medical Enclave Suite B",
            "hospital_name": "Smart Hospital Central",
            "department": "Neurosurgery",
            "shift": "Evening",
            "status": "Active"
        }, cookies=cookies)
        self.assertEqual(update_res.status_code, 200)

        # Delete doctor
        del_res = self.client.delete(f'/api/doctors/{doc_id}', cookies=cookies)
        self.assertEqual(del_res.status_code, 200)

    def test_11_nurse_crud_operations(self):
        nurse_username = "nurse_anita_test"
        db = SessionLocal()
        old_u = db.query(User).filter(User.username == nurse_username).first()
        if old_u:
            db.query(Nurse).filter(Nurse.user_id == old_u.id).delete()
            db.delete(old_u)
            db.commit()
        db.close()

        # Create nurse
        admin_login = self.client.post('/login', data={'username': 'admin', 'password': 'admin123'})
        cookies = admin_login.cookies
        create_res = self.client.post('/api/nurses', json={
            "name": "Nurse Anita Roy",
            "age": 31,
            "department": "ICU",
            "phone": "+91 92222 33333",
            "address": "88 Nurse Quarters",
            "hospital_name": "Smart Hospital Central",
            "shift": "Night",
            "username": nurse_username,
            "temporary_password": "NurseTemp@123"
        }, cookies=cookies)
        self.assertEqual(create_res.status_code, 201)
        nurse_id = create_res.json()["nurse_id"]

        # Read nurse
        get_res = self.client.get(f'/api/nurses/{nurse_id}', cookies=cookies)
        self.assertEqual(get_res.status_code, 200)
        self.assertEqual(get_res.json()["name"], "Nurse Anita Roy")

        # Update nurse
        update_res = self.client.put(f'/api/nurses/{nurse_id}', json={
            "name": "Nurse Anita Roy Sen",
            "department": "Emergency",
            "phone": "+91 92222 44444",
            "address": "88 Nurse Quarters",
            "hospital_name": "Smart Hospital Central",
            "shift": "Rotational",
            "status": "Active"
        }, cookies=cookies)
        self.assertEqual(update_res.status_code, 200)

        # Delete nurse
        del_res = self.client.delete(f'/api/nurses/{nurse_id}', cookies=cookies)
        self.assertEqual(del_res.status_code, 200)

    def test_12_admin_stats_endpoint(self):
        admin_login = self.client.post('/login', data={'username': 'admin', 'password': 'admin123'})
        cookies = admin_login.cookies
        res = self.client.get('/api/admin/stats', cookies=cookies)
        self.assertEqual(res.status_code, 200)
        stats = res.json()
        self.assertIn("patients", stats)
        self.assertIn("doctors", stats)
        self.assertIn("nurses", stats)
    def test_13_admin_file_templates_render(self):
        # Verify routes for templates moved to admin folder
        res_apt = self.client.get('/appointments')
        self.assertEqual(res_apt.status_code, 200)
        self.assertIn("Appointments", res_apt.text)

        res_comm = self.client.get('/communication')
        self.assertEqual(res_comm.status_code, 200)
        self.assertIn("Communication", res_comm.text)

        res_denied = self.client.get('/access-denied')
        self.assertEqual(res_denied.status_code, 403)
        self.assertIn("Access Denied", res_denied.text)

        admin_login = self.client.post('/login', data={'username': 'admin', 'password': 'admin123'})
        res_pwd = self.client.get('/change-password', cookies=admin_login.cookies)
        self.assertEqual(res_pwd.status_code, 200)
        self.assertIn("Change Temporary Password", res_pwd.text)


if __name__ == '__main__':
    unittest.main()

