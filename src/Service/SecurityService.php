<?php

namespace App\Service;

use App\Entity\Account;
use App\Repository\AccountRepository;
use App\Utils\Tools;
use App\Service\Exception\UploadException;
use App\Service\UploadService;

class SecurityService
{
    private AccountRepository $accountRepository;
    private UploadService $uploadService;

    public function __construct()
    {
        $this->accountRepository = new AccountRepository();
        $this->uploadService = new UploadService();
    }

    public function register(array $account): string 
    {
        //1 vérifier si les champs sont remplis
        if (
            empty($account["firstname"]) || 
            empty($account["lastname"]) ||
            empty($account["email"]) ||
            empty($account["password"]) ||
            empty($account["confirm-password"])
        ) {
            return "Veuillez remplir tous les champs du formulaire";
        }

        //2 valider les formats
        if (!filter_var($account["email"], FILTER_VALIDATE_EMAIL)) {
            return "Veuillez saisir un email valide";
        }

        //3 vérifier si les 2 mots de passe sont identiques
        if ($account["password"] != $account["confirm-password"]) {
            return "Les 2 mots de passe ne sont pas identiques";
        }

        //4 nettoyer les données
        Tools::sanitize_array($account);

        //5 vérifier si le compte existe déja
        if ($this->accountRepository->isAccountExistsByEmail($account["email"])) {
            return "Le compte existe déja";
        }

        //6 Créer un objet Account
        $user = new Account($account["email"], $account["password"]);
        $user
            ->setFirstname($account["firstname"])
            ->setLastname($account["lastname"]);
        
        //7 hasher le password
        $user->hashPassword();

        //8 Importer une image (Optionnel)
        if (isset($_FILES["image"]) && !empty($_FILES["image"]["tmp_name"])) {
            try {
                $image = $this->uploadService->uploadFile($_FILES["image"]);
                $user->setImage($image);
            } catch(UploadException $e) {}
        }

        //9 ajouter le compte
        if ($this->accountRepository->addAccount($user)->getId() == null) {
            return "Enregistrement impossible";
        };

        return "Le compte : " . $user->getEmail() . " a été ajouté en BDD";
    }

    public function logout(): void 
    {
        //détruire la session
        session_destroy();
        //Supprime le cookie
        unset($_COOKIE["PHPSESSID"]);
        //Redirection vers accueil
        header('Location: /');
        //echo "déconnecté";
        //header("Refresh:2; url=/");
    }

    public function login(array $account): string 
    {
        //1 vérifier si les champs sont remplis
        if (
            empty($account["email"]) ||
            empty($account["password"])
        ) {
            return "Veuillez remplir tous les champs du formulaire";
        }

        //2 nettoyer les données
        Tools::sanitize_array($account);

        //3 Récupération du compte
        $user = $this->accountRepository->findAccountByEmail($account["email"]);

        //5 vérifier si le compte n'existe pas
        if ($user == null) {
            return "Les informations de connexion sont incorrectes";
        }

        if (!$user->verifyPassword($account["password"])) {
            return "Les informations de connexion sont incorrectes";
        }
        //Super globale de session
        $_SESSION["connected"] = true;
        $_SESSION["email"] = $user->getEmail();
        $_SESSION["firstname"] = $user->getFirstname();
        $_SESSION["lastname"] = $user->getLastname();
        $_SESSION["id"] = $user->getId();
        $_SESSION["image"] = $user->getImage();
        
        return "Vous etes connecté";
    }
}
