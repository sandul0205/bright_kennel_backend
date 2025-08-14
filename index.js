// index.js

const express    = require('express');
const mysql      = require('mysql');
const bodyParser = require('body-parser');
const cors       = require('cors');
const jwt        = require('jsonwebtoken');
const multer     = require('multer');
const path       = require('path');
const fs         = require('fs');
const bcrypt     = require('bcrypt');

app.use(bodyParser.json());

const SECRET_KEY = '857637332672adc8cb9cded91354601b64ed97f29f2e135ba079cb18fdada3e968921889772edd28c7be862359d74dcbbd27b7388623a671cec7545f3b9796c41be393e040f50caf9400211929a6183c1a2335214753df8ac346600cdae9de5523d48ef872e4e1317901cf8eef3aba68ae98e3e91a9598881a10a7c3381149c4dd67ab6a89c2fbccf63ec13f7df6a237ae33fad98a8f6b73bc632b2c3ae5a7ceb3d4835da0cf113886b8949254ca61f6ac541badd2ead9fc16647936cfb9ea62ab8c1f4e6cded44c429eb201292f9b3056c3ff89cb3c664350ea8ecd6f6095035fb1a2ca0a99af75d740a6528168773d4ae601cc12098406b21f9850a456b889';
const BASE_URL   = 'https://bright-kennel-backend.onrender.com';
app.use(cors({
  origin: true,                 // reflect request origin
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Make sure preflight OPTIONS doesn’t 404
app.options('*', cors());

// parse JSON
app.use(express.json());
// MySQL Pool
// const pool = mysql.createPool({
//   connectionLimit: 10,
//   host:            'localhost',
//   user:            'root',
//   password:        '',
//   database:        'golden_kennel'
// });
// pool.on('error', err => console.error('MySQL pool error:', err.code));

const pool = mysql.createPool({
  host: '162.0.235.87',   // local end of the tunnel
  port: 3307,          // the -L port you set
  user: 'brigbnel_sandul0205',          // your cPanel-prefixed MySQL user
  password: 'mishubaba@0205',     // that user's password
  database: 'brigbnel_bright_kennel',
  waitForConnections: true,
  connectionLimit: 10,
});

// // quick startup test
// pool.query('SELECT 1', (err) => {
//   if (err) console.error('MySQL connect failed:', err);
//   else console.log('MySQL pool connected via SSH tunnel');
// });

// JWT middleware
function verifyToken(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).send({ success:false, message:'No token provided' });
  const token = auth.split(' ')[1];
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(403).send({ success:false, message:'Failed to authenticate token' });
    req.petId = decoded.petId;
    next();
  });
}

// Multer setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir);
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${req.petId}-${Date.now()}${ext}`);
  }
});
const upload = multer({ storage });
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


// PUBLIC — upload product image
app.post('/upload_product_image', upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ success:false, message:'No file received' });
  const url = `${BASE_URL}/uploads/${req.file.filename}`;
  res.json({ success:true, url });
});


app.post('/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email and password required' });
  }

  // 🔁 use the actual table you keep logins in
  pool.query('SELECT petId, email, password FROM pet WHERE email = ? LIMIT 1', [email], (err, results) => {
    if (err) {
      console.error('Login DB error:', err);
      return res.status(500).json({ success: false, message: 'Server error' });
    }
    if (results.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const user = results[0];
    const stored = user.password || '';

    // If password looks like a bcrypt hash, use bcrypt; else compare plaintext.
    const finishLogin = (isMatch) => {
      if (!isMatch) return res.status(401).json({ success: false, message: 'Invalid credentials' });

      // ✅ issue a real JWT (you already have SECRET_KEY)
      const token = jwt.sign({ petId: user.petId }, SECRET_KEY, { expiresIn: '7d' });

      return res.json({
        success: true,
        token,
        pet: { petId: user.petId }
      });
    };

    if (stored.startsWith('$2a$') || stored.startsWith('$2b$') || stored.startsWith('$2y$')) {
      // bcrypt hash
      bcrypt.compare(password, stored, (cmpErr, isMatch) => {
        if (cmpErr) {
          console.error('bcrypt compare error:', cmpErr);
          return res.status(500).json({ success: false, message: 'Server error' });
        }
        finishLogin(isMatch);
      });
    } else {
      // plaintext
      finishLogin(password === stored);
    }
  });
});



// PUBLIC — signup
app.post('/signup', (req, res) => {
  const { name, age, breed, gender, type, ownerName, email, password, phone, suitableWeight } = req.body;
  if (!name||!email||!password||!phone) return res.status(400).json({ success:false, message:'Required fields missing' });

  bcrypt.hash(password, 10, (hashErr, hash) => {
    if (hashErr) return res.status(500).json({ success:false, message:'Server error' });

    const sql = `
      INSERT INTO pet (name,age,breed,gender,type,ownerName,email,password,phone,suitableWeight)
      VALUES (?,?,?,?,?,?,?,?,?,?)
    `;
    const params = [name, Number(age)||0, breed, gender, type, ownerName, email, hash, phone, Number(suitableWeight)||0];
    pool.query(sql, params, (err, result) => {
      if (err) return res.status(500).json({ success:false, message:err.message });
      res.json({ success:true, insertId: result.insertId });
    });
  });
});


// PROTECTED — get pet data
app.post('/pet_data', verifyToken, (req, res) => {
  const { petId } = req.body;
  if (petId != req.petId) return res.status(403).send({ success:false, message:'Access denied' });

  pool.query('SELECT * FROM pet WHERE petId=?', [petId], (err, rows) => {
    if (err) return res.status(500).send({ success:false, message:'Server error' });
    if (!rows.length) return res.status(404).send({ success:false, message:'Pet not found' });
    res.send({ success:true, pet:rows[0] });
  });
});

// PROTECTED — update pet data
app.post('/update_pet', verifyToken, (req, res) => {
  const {
    petId,
    name,
    age,
    breed,
    gender,
    type,
    ownerName,
    email,
    password,
    phone,
    suitableWeight
  } = req.body;

  // ensure the caller is updating their own record
  if (petId != req.petId) {
    return res.status(403).json({ success: false, message: 'Access denied' });
  }

  // helper to run the UPDATE and send the notification
  function doUpdate(sql, params) {
    pool.query(sql, params, (err, result) => {
      if (err) {
        console.error('Update DB error:', err);
        return res.status(500).json({ success: false, message: 'Server error' });
      }
      if (!result.affectedRows) {
        return res.json({ success: false, message: 'Pet not found' });
      }
      // log a notification
      pool.query(
        'INSERT INTO notifications (petId,message) VALUES (?,?)',
        [petId, 'Your profile information was updated.'],
        () => {}
      );
      res.json({ success: true, message: 'Pet updated successfully' });
    });
  }

  // If a new password was provided, hash it first...
  if (password && password.trim().length) {
    bcrypt.hash(password, 10, (hashErr, hashed) => {
      if (hashErr) {
        console.error('Bcrypt hash error:', hashErr);
        return res.status(500).json({ success: false, message: 'Server error' });
      }
      const sql = `
        UPDATE pet
        SET
          name = ?, age = ?, breed = ?, gender = ?, type = ?,
          ownerName = ?, email = ?, password = ?, phone = ?, suitableWeight = ?
        WHERE petId = ?
      `;
      const params = [
        name, age, breed, gender, type,
        ownerName, email, hashed, phone, suitableWeight,
        petId
      ];
      doUpdate(sql, params);
    });
  } else {
    // No password change — omit password from the UPDATE
    const sql = `
      UPDATE pet
      SET
        name = ?, age = ?, breed = ?, gender = ?, type = ?,
        ownerName = ?, email = ?, phone = ?, suitableWeight = ?
      WHERE petId = ?
    `;
    const params = [
      name, age, breed, gender, type,
      ownerName, email, phone, suitableWeight,
      petId
    ];
    doUpdate(sql, params);
  }
});


// PROTECTED — update pet password
app.post('/update_pet_password', verifyToken, (req, res) => {
  const { petId, currentPassword, newPassword } = req.body;
  if (petId != req.petId) return res.status(403).send({ success:false, message:'Access denied' });

  pool.query('SELECT password FROM pet WHERE petId=?', [petId], (err, results) => {
    if (err) return res.status(500).send({ success:false, message:'Server error' });
    if (!results.length) return res.send({ success:false, message:'Pet not found' });
    if (results[0].password !== currentPassword) return res.send({ success:false, message:'Current password is incorrect' });

    pool.query('UPDATE pet SET password=? WHERE petId=?', [newPassword, petId], (err2, res2) => {
      if (err2) return res.status(500).send({ success:false, message:'Server error' });
      if (!res2.affectedRows) return res.send({ success:false, message:'Pet not found' });

      // notification
      pool.query(
        'INSERT INTO notifications (petId,message) VALUES (?,?)',
        [petId, 'Your password was changed successfully.'],
        () => {}
      );

      res.send({ success:true, message:'Password updated successfully' });
    });
  });
});

// PROTECTED — get today’s activities
app.post('/activities_data', verifyToken, (req, res) => {
  const { petId } = req.body;
  if (petId != req.petId) return res.status(403).send({ success:false, message:'Access denied' });

  const sql = `
    SELECT activityId, petId, activityType, duration, DATE(date) AS date
    FROM activities
    WHERE petId = ? AND DATE(date) = CURDATE()
    ORDER BY date DESC
  `;
  pool.query(sql, [petId], (err, rows) => {
    if (err) return res.status(500).send({ success:false, message:'Server error' });
    res.send({ success:true, activities: rows });
  });
});

// PROTECTED — get vet visits
app.post('/vetvisit_data', verifyToken, (req, res) => {
  const { petId } = req.body;
  if (petId !== req.petId) return res.status(403).send({ success:false, message:'Access denied' });

  const sql = `
    SELECT visitId, visitedReason, date AS visitDate, currentWeight,
           nextVisitDate, nextVisitReason, nextVaccineDate, nextVaccineName
    FROM vetvisit
    WHERE petId = ?
    ORDER BY date DESC
  `;
  pool.query(sql, [petId], (err, rows) => {
    if (err) return res.status(500).send({ success:false, message:'Server error' });
    res.send({ success:true, visits: rows });
  });
});

// PROTECTED — update profile picture
app.post('/update_profile_picture', verifyToken, upload.single('profilePic'), (req, res) => {
  if (!req.file) return res.status(400).send({ success:false, message:'No file uploaded' });
  const petId = req.petId;

  // cleanup old, then update...
  pool.query('SELECT profilePic FROM pet WHERE petId=?', [petId], (selErr, selRows) => {
    if (selErr) return res.status(500).send({ success:false, message:'Server error' });

    if (selRows[0].profilePic) {
      const filename = selRows[0].profilePic.replace(`${BASE_URL}/uploads/`, '');
      fs.unlink(path.join(__dirname,'uploads',filename), ()=>{});
    }

    const fullUrl = `${BASE_URL}/uploads/${req.file.filename}`;
    pool.query('UPDATE pet SET profilePic=? WHERE petId=?', [fullUrl,petId], (updErr,updRes) => {
      if (updErr) return res.status(500).send({ success:false, message:'Server error' });
      if (!updRes.affectedRows) return res.status(404).send({ success:false, message:'Pet not found' });

      // notification
      pool.query(
        'INSERT INTO notifications (petId,message) VALUES (?,?)',
        [petId, 'Your profile picture was updated.'],
        () => {}
      );

      res.send({ success:true, message:'Profile picture updated', profilePic:fullUrl });
    });
  });
});


// PUBLIC — get all products
app.get('/products', (req, res) => {
  pool.query('SELECT * FROM store', (err, rows) => {
    if (err) return res.status(500).send({ success:false, message:'Server error' });
    res.send({ success:true, products: rows });
  });
});

// PUBLIC — get product by ID
app.get('/product/:id', (req, res) => {
  const productId = Number(req.params.id);
  pool.query('SELECT * FROM store WHERE productId=?', [productId], (err, rows) => {
    if (err) return res.status(500).send({ success:false, message:'Server error' });
    if (!rows.length) return res.status(404).send({ success:false, message:'Product not found' });
    res.send({ success:true, product: rows[0] });
  });
});

// PROTECTED — add to cart
app.post('/add_to_cart', verifyToken, (req, res) => {
  const petId = req.petId;
  const { productId, quantity } = req.body;
  if (!productId||typeof productId!=='number'||productId<=0) return res.status(400).send({ success:false, message:'Invalid productId' });
  const qtyToInsert = (typeof quantity==='number'&&quantity>0)?quantity:1;

  pool.query('SELECT quantity FROM cart_items WHERE pet_id=? AND product_id=?',[petId,productId], (findErr, findRows) => {
    if (findErr) return res.status(500).send({ success:false, message:'Server error' });

    if (findRows.length) {
      const newQty = findRows[0].quantity + qtyToInsert;
      pool.query('UPDATE cart_items SET quantity=? WHERE pet_id=? AND product_id=?',[newQty,petId,productId], (updErr) => {
        if (updErr) return res.status(500).send({ success:false, message:'Server error' });
        res.send({ success:true, message:`Updated quantity to ${newQty}` });

        // notification
        pool.query(
          'INSERT INTO notifications (petId,message) VALUES (?,?)',
          [petId, `Updated cart: product ${productId} now qty ${newQty}.`],
          () => {}
        );
      });
    }
    else {
      pool.query('INSERT INTO cart_items (pet_id,product_id,quantity) VALUES (?,?,?)',[petId,productId,qtyToInsert], (insErr) => {
        if (insErr) return res.status(500).send({ success:false, message:'Server error' });
        res.send({ success:true, message:`Added product ${productId} (qty: ${qtyToInsert}) to cart` });

        // notification
        pool.query(
          'INSERT INTO notifications (petId,message) VALUES (?,?)',
          [petId, `Added to cart: product ${productId} (qty ${qtyToInsert}).`],
          () => {}
        );
      });
    }
  });
});

// PROTECTED — get full cart
app.get('/my_cart', verifyToken, (req, res) => {
  const petId = req.petId;
  const sql = `
    SELECT c.cart_item_id, c.product_id, c.quantity,
           s.name AS product_name, s.price AS product_price,
           s.discount AS product_discount, s.image AS product_image
    FROM cart_items c
    JOIN store s ON c.product_id=s.productId
    WHERE c.pet_id=?
  `;
  pool.query(sql, [petId], (err, rows) => {
    if (err) return res.status(500).send({ success:false, message:'Server error' });
    res.send({ success:true, cartItems:rows });
  });
});

// PROTECTED — get cart count
app.get('/cart_count', verifyToken, (req, res) => {
  const petId = req.petId;
  pool.query('SELECT COUNT(*) AS itemCount FROM cart_items WHERE pet_id=?',[petId], (err, rows) => {
    if (err) return res.status(500).send({ success:false, message:'Server error' });
    res.send({ success:true, count: rows[0].itemCount || 0 });
  });
});

// PROTECTED — remove from cart
app.post('/remove_from_cart', verifyToken, (req, res) => {
  const petId = req.petId;
  const { productId } = req.body;
  if (!productId || typeof productId!=='number') return res.status(400).send({ success:false, message:'Invalid productId' });

  pool.query('DELETE FROM cart_items WHERE pet_id=? AND product_id=?',[petId,productId], (err, result) => {
    if (err) return res.status(500).send({ success:false, message:'Server error' });
    if (!result.affectedRows) return res.send({ success:false, message:'Item not found' });

    res.send({ success:true, message:'Item removed' });

    // notification
    pool.query(
      'INSERT INTO notifications (petId,message) VALUES (?,?)',
      [petId, `Removed product ${productId} from cart.`],
      () => {}
    );
  });
});

// PROTECTED — buy now
app.post('/buy_now', verifyToken, (req, res) => {
  const petId = req.petId;
  const { productId, quantity } = req.body;
  if (!productId||typeof productId!=='number'||!quantity||typeof quantity!=='number') {
    return res.status(400).send({ success:false, message:'Invalid input' });
  }

  pool.query('SELECT price,discount FROM store WHERE productId=?',[productId], (stockErr, stockRows) => {
    if (stockErr) return res.status(500).send({ success:false, message:'Server error' });
    if (!stockRows.length) return res.status(404).send({ success:false, message:'Product not found' });

    const { price, discount } = stockRows[0];
    const discountedPrice = price*(1 - discount/100);

    pool.query(
      'INSERT INTO orders (pet_id,product_id,quantity,price_at_sale) VALUES (?,?,?,?)',
      [petId,productId,quantity,discountedPrice],
      (orderErr) => {
        if (orderErr) return res.status(500).send({ success:false, message:'Server error' });
        res.send({ success:true, message:`Order recorded: ${quantity}× product ${productId}` });

        // notification
        pool.query(
          'INSERT INTO notifications (petId,message) VALUES (?,?)',
          [petId, `Your order for product ${productId} qty ${quantity} has been placed.`],
          () => {}
        );
      }
    );
  });
});

// PROTECTED — checkout all
app.post('/checkout', verifyToken, (req, res) => {
  const petId = req.petId;
  const cartSql = `
    SELECT c.product_id, c.quantity, s.price, s.discount
    FROM cart_items c
    JOIN store s ON c.product_id=s.productId
    WHERE c.pet_id=?
  `;
  pool.query(cartSql, [petId], (cartErr, cartRows) => {
    if (cartErr) return res.status(500).send({ success:false, message:'Server error' });
    if (!cartRows.length) return res.status(400).send({ success:false, message:'Your cart is empty' });

    const ordersData = cartRows.map(item => {
      const unitPrice = item.price*(1-item.discount/100);
      return [petId, item.product_id, item.quantity, unitPrice];
    });

    pool.getConnection((connErr, connection) => {
      if (connErr) return res.status(500).send({ success:false, message:'Server error' });
      connection.beginTransaction(txErr => {
        if (txErr) {
          connection.release();
          return res.status(500).send({ success:false, message:'Server error' });
        }
        connection.query(
          'INSERT INTO orders (pet_id,product_id,quantity,price_at_sale) VALUES ?',
          [ordersData],
          orderErr => {
            if (orderErr) {
              return connection.rollback(() => {
                connection.release();
                res.status(500).send({ success:false, message:'Server error' });
              });
            }
            connection.query('DELETE FROM cart_items WHERE pet_id=?',[petId], delErr => {
              if (delErr) {
                return connection.rollback(() => {
                  connection.release();
                  res.status(500).send({ success:false, message:'Server error' });
                });
              }
              connection.commit(commitErr => {
                if (commitErr) {
                  return connection.rollback(() => {
                    connection.release();
                    res.status(500).send({ success:false, message:'Server error' });
                  });
                }
                connection.release();
                res.send({ success:true, message:'Checkout complete! Your order has been placed.' });

                // notification
                pool.query(
                  'INSERT INTO notifications (petId,message) VALUES (?,?)',
                  [petId, `Your checkout of ${cartRows.length} items was successful.`],
                  () => {}
                );
              });
            });
          }
        );
      });
    });
  });
});


// PROTECTED — create appointment
app.post('/appointments', verifyToken, (req, res) => {
  const petId = req.petId;
  let { service, serviceType, preferred_date, preferred_time, notes } = req.body;

  // if your UI only supplies one “service” dropdown,
  // just default serviceType to the same:
  if (!serviceType) serviceType = service;

  // validate
  if (!service || !preferred_date || !preferred_time) {
    return res
      .status(400)
      .json({ success: false, message: 'Please fill all required fields.' });
  }

  const dateOnly = new Date(preferred_date);
  const dateTime = new Date(`${preferred_date}T${preferred_time}`);
  if (isNaN(dateOnly) || isNaN(dateTime)) {
    return res
      .status(400)
      .json({ success: false, message: 'Invalid date or time.' });
  }

  pool.query(
    `INSERT INTO appointments
       (petId, service, serviceType, preferred_date, preferred_time, notes)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [ petId, service.trim(), serviceType.trim(), preferred_date, preferred_time, notes || null ],
    (err, result) => {
      if (err) {
        console.error('Appointment DB error:', err);
        return res.status(500).json({ success: false, message: 'Server error.' });
      }

      // log notification
      pool.query(
        'INSERT INTO notifications (petId,message) VALUES (?,?)',
        [ petId, `Appointment for ${preferred_date} at ${preferred_time} created.` ],
        () => {}
      );

      res.json({
        success: true,
        message: 'Appointment created',
        appointmentId: result.insertId
      });
    }
  );
});


// PROTECTED — list appointments
app.get('/appointments', verifyToken, (req, res) => {
  const petId = req.petId;
  pool.query(
    `SELECT appointmentId, service, serviceType,
            CONCAT(preferred_date,'T',preferred_time) AS date,
            notes, status
     FROM appointments
     WHERE petId=?
     ORDER BY preferred_date DESC, preferred_time DESC`,
    [petId],
    (err, rows) => {
      if (err) return res.status(500).send({ success:false, message:'Server error' });
      res.send({ success:true, appointments: rows });
    }
  );
});

// PROTECTED — update appointment
app.post('/update_appointment', verifyToken, (req, res) => {
  const petId = req.petId;
  const { appointmentId, newDate } = req.body;
  if (!appointmentId||!newDate) return res.status(400).send({ success:false, message:'Invalid input' });

  const dt = new Date(newDate);
  if (isNaN(dt)) return res.status(400).send({ success:false, message:'Invalid newDate' });
  const yyyy = dt.getFullYear().toString().padStart(4,'0');
  const mm   = (dt.getMonth()+1).toString().padStart(2,'0');
  const dd   = dt.getDate().toString().padStart(2,'0');
  const hh   = dt.getHours().toString().padStart(2,'0');
  const min  = dt.getMinutes().toString().padStart(2,'0');
  const dateOnly = `${yyyy}-${mm}-${dd}`;
  const timeOnly = `${hh}:${min}:00`;

  pool.query(
    `UPDATE appointments
     SET preferred_date=?, preferred_time=?, status=
       CASE WHEN status='Approved' THEN 'Pending' ELSE 'Scheduled' END
     WHERE appointmentId=? AND petId=?`,
    [dateOnly, timeOnly, appointmentId, petId],
    (err, result) => {
      if (err) return res.status(500).send({ success:false, message:'Server error' });
      if (!result.affectedRows) return res.status(404).send({ success:false, message:'Appointment not found' });

      // notification
      pool.query(
        'INSERT INTO notifications (petId,message) VALUES (?,?)',
        [petId, `Appointment #${appointmentId} rescheduled to ${dateOnly} ${timeOnly}.`],
        () => {}
      );

      res.send({ success:true, message:'Appointment rescheduled' });
    }
  );
});


// PUBLIC — list all pets
app.get('/pets', (req, res) => {
  pool.query('SELECT petId,name,type FROM pet', (err, rows) => {
    if (err) return res.status(500).send({ success:false, message:'Server error' });
    res.send({ success:true, pets: rows });
  });
});

// PROTECTED — create diet plan
app.post('/dietplan', verifyToken, (req, res) => {
  const petId = req.petId;
  const { foodList } = req.body;
  if (!foodList||typeof foodList!=='string'||foodList.trim().length<3) {
    return res.status(400).send({ success:false, message:'foodList is required (min 3 chars)' });
  }
  pool.query(
    'INSERT INTO dietplan (petId,foodList) VALUES (?,?)',
    [petId, foodList.trim()],
    (err, result) => {
      if (err) return res.status(500).send({ success:false, message:'Server error' });
      const dietId = result.insertId;
      res.send({ success:true, message:'Diet plan created', dietId });

      // notification
      pool.query(
        'INSERT INTO notifications (petId,message) VALUES (?,?)',
        [petId, 'A new diet plan has been created for you.'],
        () => {}
      );
    }
  );
});

// PROTECTED — list diet plans
app.get('/dietplan', verifyToken, (req, res) => {
  const petId = req.petId;
  pool.query('SELECT dietId,petId,foodList FROM dietplan WHERE petId=? ORDER BY dietId DESC',[petId], (err, rows) => {
    if (err) return res.status(500).send({ success:false, message:'Server error' });
    res.send({ success:true, plans: rows });
  });
});

// PROTECTED — update diet plan
app.put('/dietplan/:dietId', verifyToken, (req, res) => {
  const petId  = req.petId;
  const dietId = parseInt(req.params.dietId,10);
  const { foodList } = req.body;
  if (!foodList||typeof foodList!=='string'||foodList.trim().length<3) {
    return res.status(400).send({ success:false, message:'foodList is required (min 3 chars)' });
  }
  pool.query('UPDATE dietplan SET foodList=? WHERE dietId=? AND petId=?',[foodList.trim(),dietId,petId], (err, result) => {
    if (err) return res.status(500).send({ success:false, message:'Server error' });
    if (!result.affectedRows) return res.status(404).send({ success:false, message:'Diet plan not found' });
    res.send({ success:true, message:'Diet plan updated' });

    // notification
    pool.query(
      'INSERT INTO notifications (petId,message) VALUES (?,?)',
      [petId, `Your diet plan (#${dietId}) was updated.`],
      () => {}
    );
  });
});

// PROTECTED — delete diet plan
app.delete('/dietplan/:dietId', verifyToken, (req, res) => {
  const petId  = req.petId;
  const dietId = parseInt(req.params.dietId,10);
  pool.query('DELETE FROM dietplan WHERE dietId=? AND petId=?',[dietId,petId], (err, result) => {
    if (err) return res.status(500).send({ success:false, message:'Server error' });
    if (!result.affectedRows) return res.status(404).send({ success:false, message:'Diet plan not found' });
    res.send({ success:true, message:'Diet plan deleted' });

    // notification
    pool.query(
      'INSERT INTO notifications (petId,message) VALUES (?,?)',
      [petId, `Your diet plan (#${dietId}) was deleted.`],
      () => {}
    );
  });
});

// List all costs for a pet
app.get('/costs/:petId', (req, res) => {
  const petId = parseInt(req.params.petId,10);
  if (!petId) return res.status(400).send({ success:false, message:'Invalid petId' });
  pool.query('SELECT costId,petId,reason,cost,date FROM costs WHERE petId=? ORDER BY date DESC',[petId],(err, rows) => {
    if (err) return res.status(500).send({ success:false, message:'Server error' });
    res.send({ success:true, costs: rows });
  });
});

// Create a new cost
app.post('/costs', (req, res) => {
  const { petId, reason, cost, date } = req.body;
  if (!petId||!reason||!cost||!date) return res.status(400).send({ success:false, message:'All fields required' });
  pool.query('INSERT INTO costs (petId,reason,cost,date) VALUES (?,?,?,?)',[petId,reason,cost,date], (err, result) => {
    if (err) return res.status(500).send({ success:false, message:'Server error' });
    res.send({ success:true, costId: result.insertId });
  });
});

// Update a cost
app.put('/costs/:costId', (req, res) => {
  const costId = parseInt(req.params.costId,10);
  const { reason, cost, date } = req.body;
  pool.query('UPDATE costs SET reason=?,cost=?,date=? WHERE costId=?',[reason,cost,date,costId], (err, result) => {
    if (err) return res.status(500).send({ success:false, message:'Server error' });
    res.send({ success:true, updated: result.affectedRows });
  });
});

// Delete a cost
app.delete('/costs/:costId', (req, res) => {
  const costId = parseInt(req.params.costId,10);
  pool.query('DELETE FROM costs WHERE costId=?',[costId], (err, result) => {
    if (err) return res.status(500).send({ success:false, message:'Server error' });
    res.send({ success:true, deleted: result.affectedRows });
  });
});

// PROTECTED — list all reminders
app.get('/reminders', verifyToken, (req, res) => {
  const petId = req.petId;
  pool.query('SELECT reminderId,reason,reminderDate,reminderTime FROM todoreminder WHERE petId=? ORDER BY reminderDate, reminderTime',[petId], (err, rows) => {
    if (err) return res.status(500).send({ success:false, message:'Server error' });
    res.send({ success:true, reminders: rows });
  });
});

// PROTECTED — create a reminder
app.post('/reminders', verifyToken, (req, res) => {
  const petId = req.petId;
  const { reason, reminderDate, reminderTime } = req.body;
  if (!reason||reason.trim().length<3) return res.status(400).send({ success:false, message:'Reason too short' });
  if (!reminderDate||!reminderTime||isNaN(new Date(`${reminderDate}T${reminderTime}`).getTime())) {
    return res.status(400).send({ success:false, message:'Invalid date or time' });
  }

  pool.query('INSERT INTO todoreminder (petId,reason,reminderDate,reminderTime) VALUES (?,?,?,?)',
    [petId, reason.trim(), reminderDate, reminderTime],
    (err, result) => {
      if (err) return res.status(500).send({ success:false, message:'Server error' });
      const reminderId = result.insertId;
      res.send({ success:true, reminderId });

      // notification
      pool.query(
        'INSERT INTO notifications (petId,message) VALUES (?,?)',
        [petId, `Reminder set for ${reminderDate} at ${reminderTime}.`],
        () => {}
      );
    }
  );
});

// PROTECTED — update a reminder
app.put('/reminders/:id', verifyToken, (req, res) => {
  const petId     = req.petId;
  const reminderId= parseInt(req.params.id,10);
  const { reason, reminderDate, reminderTime } = req.body;
  if (!reason||reason.trim().length<3||!reminderDate||!reminderTime||
      isNaN(new Date(`${reminderDate}T${reminderTime}`).getTime())) {
    return res.status(400).send({ success:false, message:'Invalid input' });
  }

  pool.query(
    'UPDATE todoreminder SET reason=?,reminderDate=?,reminderTime=? WHERE reminderId=? AND petId=?',
    [reason.trim(),reminderDate,reminderTime,reminderId,petId],
    (err, result) => {
      if (err) return res.status(500).send({ success:false, message:'Server error' });
      if (!result.affectedRows) return res.status(404).send({ success:false, message:'Not found' });
      res.send({ success:true });

      // notification
      pool.query(
        'INSERT INTO notifications (petId,message) VALUES (?,?)',
        [petId, `Reminder (#${reminderId}) rescheduled.`],
        () => {}
      );
    }
  );
});

// PROTECTED — delete a reminder
app.delete('/reminders/:id', verifyToken, (req, res) => {
  const petId     = req.petId;
  const reminderId= parseInt(req.params.id,10);

  pool.query('DELETE FROM todoreminder WHERE reminderId=? AND petId=?',[reminderId,petId], (err, result) => {
    if (err) return res.status(500).send({ success:false, message:'Server error' });
    if (!result.affectedRows) return res.status(404).send({ success:false, message:'Not found' });
    res.send({ success:true });

    // notification
    pool.query(
      'INSERT INTO notifications (petId,message) VALUES (?,?)',
      [petId, `Reminder (#${reminderId}) cancelled.`],
      () => {}
    );
  });
});

// PROTECTED — get activities (today | month)
app.post('/activities_data2', verifyToken, (req, res) => {
  const { petId, scope = 'today' } = req.body;
  if (petId !== req.petId) {
    return res.status(403).json({ success: false, message: 'Access denied' });
  }

  let sql = `
    SELECT
      activityId,
      petId,
      activityType,
      duration,
      DATE(date) AS date
    FROM activities
    WHERE petId = ?
  `;

  if (scope === 'month') {
    sql += ` AND MONTH(date)=MONTH(CURDATE()) AND YEAR(date)=YEAR(CURDATE()) ORDER BY date`;
  } else {
    sql += ` AND DATE(date)=CURDATE() ORDER BY date DESC`;
  }

  pool.query(sql, [petId], (err, rows) => {
    if (err) {
      console.error('Activities query error:', err);
      return res.status(500).json({ success: false, message: 'Server error' });
    }
    res.json({ success: true, activities: rows });
  });
});

// PROTECTED — add an activity
app.post('/activities', verifyToken, (req, res) => {
  const { activityType, duration, date } = req.body;
  if (!activityType || typeof duration !== 'number') {
    return res.status(400).json({ success: false, message: 'activityType & duration are required' });
  }

  const activityDate = date ? new Date(date) : new Date();
  pool.query(
    'INSERT INTO activities (petId, activityType, duration, date) VALUES (?, ?, ?, ?)',
    [req.petId, activityType, duration, activityDate],
    (err, result) => {
      if (err) {
        console.error('Insert activity error:', err);
        return res.status(500).json({ success: false, message: 'Server error' });
      }
      res.json({ success: true, activityId: result.insertId });
    }
  );
});


// ADMIN CRUD — list products
app.get('/admin/products', (req, res) => {
  pool.query('SELECT * FROM store', (err, rows) => {
    if (err) return res.status(500).send({ success:false, message:'Server error' });
    res.send({ success:true, products: rows });
  });
});

// ADMIN CRUD — get one product
app.get('/admin/products/:id', (req, res) => {
  const id=Number(req.params.id);
  pool.query('SELECT * FROM store WHERE productId=?',[id], (err, rows) => {
    if (err) return res.status(500).send({ success:false, message:'Server error' });
    if (!rows.length) return res.status(404).send({ success:false, message:'Not found' });
    res.send({ success:true, product: rows[0] });
  });
});

// ADMIN CRUD — create product
app.post('/admin/products', (req, res) => {
  const { name, qty, price, description, discount, petType, image } = req.body;
  if (!name||!qty||!price||!petType) return res.status(400).send({ success:false, message:'Missing required fields' });

  pool.query(
    'INSERT INTO store (name,qty,price,description,image,discount,petType) VALUES (?,?,?,?,?,?,?)',
    [name,Number(qty),parseFloat(price),description||null,image||null,Number(discount)||0,petType],
    (err, result) => {
      if (err) return res.status(500).send({ success:false, message:'Server error' });
      res.send({ success:true, productId: result.insertId });
    }
  );
});

// ADMIN CRUD — update product
app.put('/admin/products/:id', (req, res) => {
  const id=Number(req.params.id);
  const { name, qty, price, description, discount, petType, image } = req.body;
  if (!name||!qty||!price||!petType) return res.status(400).send({ success:false, message:'Missing required fields' });

  pool.query('SELECT image FROM store WHERE productId=?',[id], (err, rows) => {
    if (err) return res.status(500).send({ success:false, message:'Server error' });
    if (!rows.length) return res.status(404).send({ success:false, message:'Product not found' });

    // cleanup file if necessary
    const oldUrl = rows[0].image;
    if (oldUrl && oldUrl.includes('/uploads/')) {
      const fn=oldUrl.split('/uploads/')[1];
      try{ fs.unlinkSync(path.join(__dirname,'uploads',fn)); }catch(e){}
    }

    pool.query(
      'UPDATE store SET name=?,qty=?,price=?,description=?,image=?,discount=?,petType=? WHERE productId=?',
      [name,Number(qty),parseFloat(price),description||null,image||null,Number(discount)||0,petType,id],
      upErr => {
        if (upErr) return res.status(500).send({ success:false, message:'Server error' });
        res.send({ success:true });
      }
    );
  });
});

// ADMIN CRUD — delete product
app.delete('/admin/products/:id', (req, res) => {
  const id=Number(req.params.id);
  pool.query('SELECT image FROM store WHERE productId=?', [id], (err, rows) => {
    if (err) return res.status(500).send({ success:false, message:'Server error' });
    if (!rows.length) return res.status(404).send({ success:false, message:'Product not found' });

    const imageUrl = rows[0].image;
    if (imageUrl && imageUrl.includes('/uploads/')) {
      const fn=imageUrl.split('/uploads/')[1];
      try{ fs.unlinkSync(path.join(__dirname,'uploads',fn)); }catch(e){}
    }

    pool.query('DELETE FROM orders WHERE product_id=?',[id], () => {
      pool.query('DELETE FROM cart_items WHERE product_id=?',[id], () => {
        pool.query('DELETE FROM store WHERE productId=?',[id], (delErr,result) => {
          if (delErr) return res.status(500).send({ success:false, message:'Server error deleting product' });
          res.send({ success:true, message:'Product and all references removed' });
        });
      });
    });
  });
});


// ADMIN — create diet plan for any pet (no auth)
app.post('/adminDietplan', (req, res) => {
  const { petId, foodList } = req.body;
  if (!petId||typeof petId!=='number'||!foodList||foodList.trim().length<3) {
    return res.status(400).send({ success:false, message:'petId (number) and foodList (min 3 chars) are required' });
  }
  pool.query('INSERT INTO dietplan (petId,foodList) VALUES (?,?)',[petId,foodList.trim()], (err,result) => {
    if (err) return res.status(500).send({ success:false, message:'Server error' });
    res.send({ success:true, message:'Diet plan created', dietId: result.insertId });
  });
});

// ADMIN — list appointments
app.get('/admin/appointments', (req, res) => {
  const sql=`
    SELECT a.appointmentId,a.petId,p.name AS petName,a.service,a.serviceType,
           a.preferred_date,a.preferred_time,a.notes,a.status
    FROM appointments a
    JOIN pet p ON a.petId=p.petId
    ORDER BY a.preferred_date DESC,a.preferred_time DESC
  `;
  pool.query(sql, (err,rows) => {
    if (err) return res.status(500).json({ success:false, message:'Server error' });
    res.json({ success:true, appointments:rows });
  });
});

// ADMIN — update appointment status & notify
app.put('/admin/appointments/:id/status', (req, res) => {
  const appointmentId = Number(req.params.id);
  const { status, note } = req.body;
  if (!['Pending','Approved','Rejected'].includes(status)) return res.status(400).json({ success:false, message:'Invalid status' });
  if (!note||!note.trim()) return res.status(400).json({ success:false, message:'Note is required' });

  pool.query('UPDATE appointments SET status=? WHERE appointmentId=?',[status,appointmentId], (err,result) => {
    if (err) return res.status(500).json({ success:false, message:'Server error' });
    if (!result.affectedRows) return res.status(404).json({ success:false, message:'Appointment not found' });

    pool.query('SELECT petId FROM appointments WHERE appointmentId=?',[appointmentId], (err2,rows2) => {
      if (err2||!rows2.length) {
        console.error('Could not fetch petId for notification',err2);
        return res.json({ success:true, message:'Status updated (no notification)' });
      }
      const petId = rows2[0].petId;
      const msg   = `Your appointment has been ${status.toLowerCase()}. Note: ${note.trim()}`;

      pool.query('INSERT INTO notifications (petId,message) VALUES (?,?)',[petId,msg], (err3) => {
        if (err3) console.error('Failed to insert notification',err3);
        res.json({ success:true, message:'Status updated and notification logged' });
      });
    });
  });
});

// GET notifications for a pet
app.get('/pets/:petId/notifications', verifyToken, (req, res) => {
  const petId = Number(req.params.petId);
  pool.query('SELECT * FROM notifications WHERE petId=? ORDER BY created_at DESC',[petId], (err, rows) => {
    if (err) return res.status(500).json({ success:false, message:'Server error' });
    res.json({ success:true, notifications: rows });
  });
});

// Mark a notification read
app.put('/pets/:petId/notifications/:nid/read', verifyToken, (req, res) => {
  const petId = Number(req.params.petId);
  const nid   = Number(req.params.nid);
  pool.query('UPDATE notifications SET checked=1 WHERE notificationId=? AND petId=?',[nid,petId], (err, result) => {
    if (err) return res.status(500).json({ success:false, message:'Server error' });
    if (!result.affectedRows) return res.status(404).json({ success:false, message:'Not found for this pet' });
    res.json({ success:true, message:'Marked as read' });
  });
});


// OPEN — create vet visit as admin
app.post('/adminVetvisit', (req, res) => {
  const { petId, visitedReason, date, currentWeight, nextVisitDate, nextVisitReason, nextVaccineDate, nextVaccineName } = req.body;
  if (!petId||!visitedReason||!date||currentWeight==null) {
    return res.status(400).json({ success:false, message:'petId, visitedReason, date & currentWeight required' });
  }
  const sql=`
    INSERT INTO vetvisit
      (petId,visitedReason,date,currentWeight,nextVisitDate,nextVisitReason,nextVaccineDate,nextVaccineName)
    VALUES (?,?,?,?,?,?,?,?)
  `;
  const params=[petId,visitedReason.trim(),date,Number(currentWeight),nextVisitDate||null,nextVisitReason||null,nextVaccineDate||null,nextVaccineName||null];
  pool.query(sql, params, (err, result) => {
    if (err) return res.status(500).json({ success:false, message:'Server error' });
    res.json({ success:true, message:'Vet visit recorded by admin', visitId: result.insertId });

    // notification
    pool.query(
      'INSERT INTO notifications (petId,message) VALUES (?,?)',
      [petId, `New vet visit recorded for ${date}.`],
      () => {}
    );
  });
});

// ADMIN — fetch vet visits for any pet
app.post('/adminVetvisitData', (req, res) => {
  const { petId } = req.body;
  if (!petId) return res.status(400).json({ success:false, message:'petId is required' });
  const sql=`
    SELECT visitId, visitedReason, date AS visitDate, currentWeight,
           nextVisitDate, nextVisitReason, nextVaccineDate, nextVaccineName
    FROM vetvisit
    WHERE petId=?
    ORDER BY date DESC
  `;
  pool.query(sql,[petId], (err, rows) => {
    if (err) return res.status(500).json({ success:false, message:'Server error' });
    res.json({ success:true, visits: rows });
  });
});

// ADMIN — update a vet visit
app.put('/adminVetvisit/:visitId', (req, res) => {
  const vid = Number(req.params.visitId);
  const { visitedReason, date, currentWeight, nextVisitDate, nextVisitReason, nextVaccineDate, nextVaccineName } = req.body;
  if (!visitedReason||!date||currentWeight==null) {
    return res.status(400).json({ success:false, message:'visitedReason, date & currentWeight required' });
  }
  const sql=`
    UPDATE vetvisit SET visitedReason=?,date=?,currentWeight=?,nextVisitDate=?,nextVisitReason=?,nextVaccineDate=?,nextVaccineName=?
    WHERE visitId=?
  `;
  const params=[visitedReason.trim(),date,Number(currentWeight),nextVisitDate||null,nextVisitReason||null,nextVaccineDate||null,nextVaccineName||null,vid];
  pool.query(sql, params, (err, result) => {
    if (err) return res.status(500).json({ success:false, message:'Server error' });
    res.json({ success:true });
  });
});

// ADMIN — delete a vet visit
app.delete('/adminVetvisit/:visitId', (req, res) => {
  const vid=Number(req.params.visitId);
  pool.query('DELETE FROM vetvisit WHERE visitId=?',[vid], (err, result) => {
    if (err) return res.status(500).json({ success:false, message:'Server error' });
    res.json({ success:true });
  });
});

// ADMIN — list pending orders
app.get('/admin/orders', (req, res) => {
  const { startDate, endDate } = req.query;
  let sql=`
    SELECT o.order_id AS orderId, o.pet_id AS petId, p.name AS petName,
           o.product_id AS productId, s.name AS productName,
           o.quantity, o.price_at_sale AS priceAtSale, DATE(o.order_date) AS orderDate
    FROM orders o
    JOIN pet p ON o.pet_id=p.petId
    JOIN store s ON o.product_id=s.productId
  `;
  const params = [];
  if (startDate && endDate) {
    sql += ' WHERE DATE(o.order_date) BETWEEN ? AND ?';
    params.push(startDate, endDate);
  }
  sql += ' ORDER BY o.order_date DESC';

  pool.query(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ success:false, message:'Server error' });
    res.json({ success:true, orders: rows });
  });
});

// ADMIN — accept an order and notify (detailed transaction)
app.post('/admin/orders/:orderId/accept', (req, res) => {
  const oid = Number(req.params.orderId);
  pool.getConnection((connErr, conn) => {
    if (connErr) return res.status(500).json({ success:false, message:'Server error' });
    conn.beginTransaction(txErr => {
      if (txErr) { conn.release(); return res.status(500).json({ success:false, message:'Server error' }); }

      // fetch order for update
      conn.query(
        'SELECT pet_id,product_id,quantity,price_at_sale,order_date FROM orders WHERE order_id=? FOR UPDATE',
        [oid],
        (selErr, selRows) => {
          if (selErr || !selRows.length) {
            return conn.rollback(() => {
              conn.release();
              selErr
                ? res.status(500).json({ success:false, message:'Server error' })
                : res.status(404).json({ success:false, message:'Order not found' });
            });
          }
          const o = selRows[0];
          const totalCost = o.quantity * o.price_at_sale;

          // check stock
          conn.query('SELECT qty FROM store WHERE productId=? FOR UPDATE',[o.product_id], (stErr, stRows) => {
            if (stErr || !stRows.length || stRows[0].qty < o.quantity) {
              return conn.rollback(() => {
                conn.release();
                const msg = stErr ? 'Server error' : 'Insufficient stock';
                res.status(stErr ? 500 : 400).json({ success:false, message:msg });
              });
            }

            // insert sale
            conn.query('INSERT INTO sales (petId,productId,qty,cost,date) VALUES (?,?,?,?,?)',
              [o.pet_id, o.product_id, o.quantity, totalCost, o.order_date],
              insErr => {
                if (insErr) {
                  return conn.rollback(() => {
                    conn.release();
                    res.status(500).json({ success:false, message:'Server error' });
                  });
                }

                // decrement stock
                conn.query('UPDATE store SET qty=qty-? WHERE productId=?',[o.quantity,o.product_id], (updErr,updRes) => {
                  if (updErr || updRes.affectedRows===0) {
                    return conn.rollback(() => {
                      conn.release();
                      res.status(500).json({ success:false, message:'Server error' });
                    });
                  }

                  // delete order
                  conn.query('DELETE FROM orders WHERE order_id=?',[oid], delErr => {
                    if (delErr) {
                      return conn.rollback(() => {
                        conn.release();
                        res.status(500).json({ success:false, message:'Server error' });
                      });
                    }

                    // commit
                    conn.commit(cmErr => {
                      if (cmErr) {
                        return conn.rollback(() => {
                          conn.release();
                          res.status(500).json({ success:false, message:'Server error' });
                        });
                      }
                      conn.release();
                      res.json({ success:true, message:'Order accepted and stock updated' });

                      // notification
                      pool.query(
                        'INSERT INTO notifications (petId,message) VALUES (?,?)',
                        [o.pet_id, `Your order #${oid} has been accepted.`],
                        () => {}
                      );
                    });
                  });
                });
              }
            );
          });
        }
      );
    });
  });
});

// ADMIN — reject an order
app.delete('/admin/orders/:orderId', (req, res) => {
  const oid = Number(req.params.orderId);
  pool.query('DELETE FROM orders WHERE order_id=?',[oid], (err, result) => {
    if (err) return res.status(500).json({ success:false, message:'Server error' });
    if (!result.affectedRows) return res.status(404).json({ success:false, message:'Order not found' });
    res.json({ success:true });
  });
});

// ADMIN — sales summary
app.post('/admin/sales/summary', (req, res) => {
  const { startDate, endDate } = req.body;
  if (!startDate||!endDate) return res.status(400).json({ success:false, message:'startDate & endDate required' });

  const sql=`
    SELECT DATE(date) AS day, SUM(cost) AS totalRevenue, SUM(qty) AS totalQuantity
    FROM sales
    WHERE DATE(date) BETWEEN ? AND ?
    GROUP BY day
    ORDER BY day
  `;
  pool.query(sql,[startDate,endDate], (err, rows) => {
    if (err) return res.status(500).json({ success:false, message:'Server error' });
    const overall = rows.reduce((acc,r)=>( {
      revenue: acc.revenue + Number(r.totalRevenue),
      quantity: acc.quantity + Number(r.totalQuantity)
    }), { revenue:0, quantity:0 });
    res.json({ success:true, overall, daily: rows });
  });
});

// ADMIN — list detailed sales
app.get('/admin/sales', (req, res) => {
  const { startDate, endDate } = req.query;
  let sql=`
    SELECT s.saleId AS saleId, s.petId, p.name AS petName,
           s.productId, st.name AS productName, s.qty AS quantity,
           s.cost, DATE(s.date) AS date
    FROM sales s
    JOIN pet p ON s.petId=p.petId
    JOIN store st ON s.productId=st.productId
  `;
  const params = [];
  if (startDate && endDate) {
    sql += ' WHERE DATE(s.date) BETWEEN ? AND ?';
    params.push(startDate, endDate);
  }
  sql += ' ORDER BY s.date DESC';

  pool.query(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ success:false, message:'Server error' });
    res.json({ success:true, sales: rows });
  });
});


// Start server
app.listen(3000, () => {
  console.log('Server running on port 3000');
});
