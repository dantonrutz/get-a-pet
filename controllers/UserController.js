const User = require("../models/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const createUserToken = require("../helpers/create-user-token");
const getToken = require("../helpers/get-token");

module.exports = class UserController{
  static async register(req, res){

    const { name, email, phone, password, confirmPassword } = req.body;

    // ----- Validações ----- //
    if (!name){
      res.status(422).json({ message: "O nome é obrigatório" })
    }
    if (!email){
      res.status(422).json({ message: "O email é obrigatório" })
    }
    if (!phone){
      res.status(422).json({ message: "O telefone é obrigatório" })
    }
    if (!password){
      res.status(422).json({ message: "A senha é obrigatória" })
    }
    if (!confirmPassword){
      res.status(422).json({ message: "A confirmação de senha é obrigatória" })
    }
    if (password !== confirmPassword){
      res.status(422).json({ message: "A senha e a confirmação de senha precisam ser iguais!" })
    }

    // ----- Ver se o usuário existe ----- //
    const userExists = await User.findOne({ email: email});

    if (userExists){
      res.status(422).json({ message: "Já existe um usuário com esse email" })
      return
    }

    // ----- Criar senha ----- //
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // ----- Criar usuario ----- //
    const user = new User({
      name,
      email,
      phone,
      password: passwordHash,
    })

    try {
      const newUser = await user.save();

      await createUserToken(newUser, req, res)

      res.status(201).json({ message: "Usuário cadastrado com sucesso", newUser })
    } catch (error) {
      res.status(500).json({ message: error })
    }
  }

  static async login(req, res){
    
    const { email, password } = req.body;

    // ----- Validações ----- //
    if (!email){
      res.status(422).json({ message: "O email é obrigatório" })
    }
    if (!password){
      res.status(422).json({ message: "A senha é obrigatória" })
    }

    // ----- Ver se o usuário existe ----- //
    const loginUser = await User.findOne({ email: email});

    if (!loginUser){
      res.status(422).json({ message: "Não há usúario cadastrado com este email" })
      return
    }

    // ----- Ver se a senha é igual a senha no BD ----- //
    const checkPassword = await bcrypt.compare(password, loginUser.password);

    if (!checkPassword){
      res.status(422).json({ message: "Senha incorreta" })
      return 
    }

    // ----- Cria o token ----- //
    await createUserToken(loginUser, req, res);
  }

  static async checkUser(req, res){

    let currentUser;

    console.log(req.headers.authorization)

    if (req.headers.authorization){
      const token = getToken(req);
      const decoded = jwt.verify(token, 'nossosecret');

      currentUser = await User.findById(decoded.id);
      currentUser.password = undefined;
    } else {
      currentUser = null
    }

    res.status(200).send(currentUser);
  }

  static async getUserById(req, res){

    const id = req.params.id;

    const user = await User.findById(id).select("-password");


    if (!user){
      res.status(422).json({ message: "Usuário não encontrado" })
      return
    } 

    res.status(200).json({ user })
  }

  static async editUser(req, res){

    const id = req.params.id;

    // ----- Ver se o usuário existe ----- //
    const user = await User.findById(id);



    const { name, email, phone, password, confirmPassword } = req.body;

    let image = '';
    
    // ----- Validações ----- //
    if (!name){
      res.status(422).json({ message: "O nome é obrigatório" })
    }
    if (!email){
      res.status(422).json({ message: "O email é obrigatório" })
    }

    // ----- Ver se o usuário existe ----- //
    const userExists = await User.findOne({email: email});

    if (user.email !== email && userExists){
      res.status(422).json({ message: "Usuário não encontrado" })
      return
    }

    user.email = email;


    if (!phone){
      res.status(422).json({ message: "O telefone é obrigatório" })
    }
    if (!password){
      res.status(422).json({ message: "A senha é obrigatória" })
    }
    if (!confirmPassword){
      res.status(422).json({ message: "A confirmação de senha é obrigatória" })
    }
    if (password !== confirmPassword){
      res.status(422).json({ message: "A senha e a confirmação de senha precisam ser iguais!" })
    }
  }
}