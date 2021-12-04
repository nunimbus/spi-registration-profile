// https://mkyong.com/java/java-aes-encryption-and-decryption/

package com.nunimbus.keycloak.extensions.actions.forms;

import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.util.CookieHelper;
import org.keycloak.services.validation.Validation;
import org.keycloak.userprofile.UserProfileContext;
import org.keycloak.userprofile.ValidationException;
import org.keycloak.userprofile.UserProfile;
import org.keycloak.userprofile.UserProfileProvider;
import com.nunimbus.keycloak.extensions.actions.forms.CryptoUtils;
import com.nunimbus.keycloak.extensions.actions.forms.ASCIICharacterData;
import org.passay.PasswordGenerator;
import org.passay.CharacterRule;

import javax.ws.rs.core.MultivaluedMap;

import java.util.ArrayList;
import java.util.List;

public class RegistrationProfileGroup implements FormAction, FormActionFactory {
    public static final String PROVIDER_ID = "registration-profile-action-group";

    @Override
    public String getHelpText() {
        return "Creates a group named `admin-[username]` and adds the new user.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    @Override
    public void validate(org.keycloak.authentication.ValidationContext context) {
/*
        String eventError = Errors.INVALID_REGISTRATION;
        List<FormMessage> errors = new ArrayList<>();
        errors.add(new FormMessage(RegistrationPage.FIELD_EMAIL, Messages.MISSING_EMAIL));
        System.err.println(formData.getFirst(RegistrationPage.FIELD_PASSWORD));
        eventError = Errors.EMAIL_IN_USE;
        context.error(eventError);
        context.validationError(formData, errors);
*/
        context.success();
        return;
    }

    @Override
    public void success(FormContext context) {
    	MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    	String password = formData.getFirst(RegistrationPage.FIELD_PASSWORD);

    	UserModel user = context.getUser();
//        GroupModel group = context.getRealm().createGroup("admin-" + user.getUsername());
//        user.joinGroup(group);
        
        CharacterRule ascii = new CharacterRule(ASCIICharacterData.ASCII); 
		PasswordGenerator passwordGenerator = new PasswordGenerator();
		String key = passwordGenerator.generatePassword(128, ascii);
        String credential = context.getSession().userCredentialManager().getStoredCredentialsStream(context.getRealm(), user).findFirst().get().getValue();
		String encrypted = "";
		
		try {
			System.err.println("REGISTRATION: Creating credential encrypted values:");
	    	System.err.println(new Throwable().getStackTrace()[0].getFileName() + ":" + new Throwable().getStackTrace()[0].getLineNumber());
			encrypted = CryptoUtils.encrypt(key, credential);
			System.err.println("Encrypted:   " + encrypted.substring(0, 8));
			System.err.println("Credential:  " + credential.substring(0, 8));
			System.err.println("Key:         " + key.substring(0, 8));
			System.err.println();
			System.err.println();

			user.setSingleAttribute("encryptionKey", encrypted);
		} catch (Exception e) {
			System.err.println("ERROR: " + new Throwable().getStackTrace()[0].getFileName() + ":" + new Throwable().getStackTrace()[0].getLineNumber());
			//e.printStackTrace();
		}

		key = passwordGenerator.generatePassword(128, ascii);
		encrypted = "";
		
		try {
			System.err.println("REGISTRATION: Creating pw-encrypted values:");
	    	System.err.println(new Throwable().getStackTrace()[0].getFileName() + ":" + new Throwable().getStackTrace()[0].getLineNumber());
			encrypted = CryptoUtils.encrypt(key, password);
			System.err.println("Encrypted: " + encrypted.substring(0, 8));
			System.err.println("Password:  " + password);
			System.err.println("Key:       " + key.substring(0, 8));
			System.err.println();
			System.err.println();

//			String encryptedCookie = CryptoUtils.encrypt(key, credential);
//			context.getAuthenticationSession().setAuthNote("password", password);
//	    	CookieHelper.addCookie("passwordEncryptionKey", encryptedCookie, "/auth/realms/nunimbus"/* + event.getRealmId()*/, null, null, -1, true, true);
			user.setSingleAttribute("passwordEncryptionKey", encrypted);
		} catch (Exception e) {
			System.err.println("ERROR: " + new Throwable().getStackTrace()[0].getFileName() + ":" + new Throwable().getStackTrace()[0].getLineNumber());
			//e.printStackTrace();
		}
    }

    @Override
    public void buildPage(FormContext context, LoginFormsProvider form) {
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }


    @Override
    public void close() {

    }

    @Override
    public String getDisplayType() {
        return "Create encryption keys";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED
    };
    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }
    @Override
    public FormAction create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}