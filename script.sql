-- =======================================================================
-- TG_REGISTRA ===========================================================
-- =======================================================================

CREATE OR REPLACE TRIGGER tg_registra
BEFORE INSERT
ON login
REFERENCING NEW AS NEW
FOR EACH ROW
DECLARE
date_time TIMESTAMP;
passwd VARCHAR2(4000);
ascii_password VARCHAR2(4000);
pass_length NUMBER := LENGTH(:new.senha) / 3;
milSegundo NUMBER;
BEGIN
    date_time := SYSTIMESTAMP;
    SELECT MAX(TO_CHAR(date_time,'FF1')) INTO milSegundo FROM dual;

    -- CRIPTOGRAFAR SENHA ======================================================
    FOR i IN 1 .. 3 LOOP
            passwd := passwd || SUBSTR(:new.senha, i, 1);
        FOR j in 1 .. pass_length LOOP
            passwd := passwd || SUBSTR(:new.senha, i + (3 * j), 1);
        END LOOP;
    END LOOP;
    
    -- TRANSFORMANDO EM ASCII
    FOR x IN 1 .. LENGTH(passwd) LOOP
        
        IF ASCII(SUBSTR(passwd, x, 1)) < 100 THEN
            ascii_password := ascii_password || '0' || (milSegundo + ASCII(SUBSTR(passwd, x, 1)));
        ELSE
            ascii_password := ascii_password || (milSegundo + ASCII(SUBSTR(passwd, x, 1)));
        END IF;
    END LOOP;
    :new.senha := ascii_password;
    INSERT INTO acesso VALUES (date_time, :new.cod_login);

END;
/

-- =======================================================================
-- TG_ATUALIZA ===========================================================
-- =======================================================================
CREATE OR REPLACE TRIGGER tg_atualiza
BEFORE INSERT
ON acesso
REFERENCING NEW AS NEW
FOR EACH ROW
DECLARE
new_password VARCHAR2(4000);
milSeg NUMBER;
uncrypted_password VARCHAR2(4000);
ascii_password VARCHAR2(4000);
x NUMBER := 1;
-- MUST PLACE A PASSWORD HERE
passwd VARCHAR2(4000) := 'COTEMIG123';
BEGIN
    pr_verifica(:new.cod_login, passwd);

    SELECT MAX(TO_CHAR(data_hora,'FF1')) INTO milSeg
    FROM acesso
    WHERE cod_login = :new.cod_login;
    
    SELECT passwd INTO new_password
    FROM login
    WHERE cod_login = :new.cod_login;
    
    WHILE x < LENGTH(new_password) LOOP
        uncrypted_password := uncrypted_password || TO_NUMBER(SUBSTR(new_password, x, 3)) - milSeg;
        x := x + 3;
    END LOOP;
    
    FOR x IN 1 .. LENGTH(uncrypted_password) LOOP
        
        IF ASCII(SUBSTR(uncrypted_password, x, 1)) < 100 THEN
            ascii_password := ascii_password || '0' || (milSeg + ASCII(SUBSTR(uncrypted_password, x, 1)));
        ELSE
            ascii_password := ascii_password || (milSeg + ASCII(SUBSTR(uncrypted_password, x, 1)));
        END IF;
    
    END LOOP;

    UPDATE login 
    SET senha = ascii_password
    WHERE cod_login = :new.cod_login;
END;
/

-- =======================================================================
-- PR_VERIFICA ===========================================================
-- =======================================================================


CREATE OR REPLACE PROCEDURE pr_verifica(codigoUsuario NUMBER, senhaUsuario VARCHAR2)
AS
crypted_password VARCHAR2(4000);
uncrypted_password VARCHAR2(4000);
senhaFinal VARCHAR2(4000);
pass_length NUMBER;
dateTime TIMESTAMP;
milSegundo NUMBER;
x NUMBER := 1;
BEGIN
 
    
    SELECT login.senha INTO crypted_password
    FROM login
    WHERE cod_login = codigoUsuario;
    
    SELECT MAX(data_hora) INTO dateTime
    FROM acesso
    WHERE cod_login = codigoUsuario;
    
    SELECT MAX(TO_CHAR(dateTime,'FF1')) INTO milSegundo FROM dual;
    pass_length := LENGTH(crypted_password);
    
    WHILE x < pass_length LOOP
        uncrypted_password := uncrypted_password || CHR(TO_NUMBER(SUBSTR(crypted_password, x, 3)) - milSegundo);
        x := x + 3;
    END LOOP;

    pass_length := LENGTH(uncrypted_password);
    FOR x IN 1 .. CEIL(pass_length/3) LOOP
        IF MOD(pass_length, 3) = 0 THEN
                senhaFinal := senhaFinal || SUBSTR(uncrypted_password, x, 1);
                senhaFinal := senhaFinal || SUBSTR(uncrypted_password, x + (pass_length / 3), 1);
                senhaFinal := senhaFinal || SUBSTR(uncrypted_password, x + (pass_length / 3) + (pass_length / 3), 1);
        ELSIF MOD(pass_length, 3) = 1 THEN
            IF x = CEIL(pass_length/3) THEN
                senhaFinal := senhaFinal || SUBSTR(uncrypted_password, x, 1);
            ELSE
                senhaFinal := senhaFinal || SUBSTR(uncrypted_password, x, 1);
                senhaFinal := senhaFinal || SUBSTR(uncrypted_password, x + CEIL(pass_length / 3), 1);
                senhaFinal := senhaFinal || SUBSTR(uncrypted_password, x + CEIL(pass_length / 3) + FLOOR(pass_length / 3), 1);
            END IF;
            
        ELSIF MOD(pass_length, 3) = 2 THEN
            IF x = CEIL(pass_length/3) THEN
                senhaFinal := senhaFinal || SUBSTR(uncrypted_password, x, 1);
                senhaFinal := senhaFinal || SUBSTR(uncrypted_password, x + CEIL(pass_length / 3), 1);
            ELSE
                senhaFinal := senhaFinal || SUBSTR(uncrypted_password, x, 1);
                senhaFinal := senhaFinal || SUBSTR(uncrypted_password, x + CEIL(pass_length / 3), 1);
                senhaFinal := senhaFinal || SUBSTR(uncrypted_password, x + CEIL(pass_length / 3) + CEIL(pass_length / 3), 1);
            END IF;
        END IF;
    END LOOP;
    
    IF senhaFinal = senhaUsuario THEN
            dbms_output.put_line('Acesso Permitido!');
    ELSE
            raise_application_error(-20001, 'Acesso Negado! Senha incorreta.');
    END IF;
    
END;
/
