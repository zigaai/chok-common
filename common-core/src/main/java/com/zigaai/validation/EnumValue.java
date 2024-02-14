package com.zigaai.validation;

import com.zigaai.exception.BizIllegalArgumentException;
import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

@Target({ElementType.METHOD, ElementType.FIELD, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = EnumValue.Validator.class)
public @interface EnumValue {

    String message() default "无效的枚举值";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    @SuppressWarnings("squid:S1452")
    Class<? extends Enum<?>> enumClass();

    String enumMethod() default "contains";

    class Validator implements ConstraintValidator<EnumValue, Object> {

        private Class<? extends Enum<?>> enumClass;

        private String enumMethod;

        @Override
        public void initialize(EnumValue enumValue) {
            enumMethod = enumValue.enumMethod();
            enumClass = enumValue.enumClass();
        }

        @Override
        public boolean isValid(Object value, ConstraintValidatorContext constraintValidatorContext) {
            if (value == null) {
                return Boolean.TRUE;
            }
            if (enumClass == null || enumMethod == null) {
                return Boolean.TRUE;
            }
            Class<?> valueClass = value.getClass();
            try {
                Method method = enumClass.getDeclaredMethod(enumMethod, valueClass);
                if (!Boolean.TYPE.equals(method.getReturnType()) && !Boolean.class.equals(method.getReturnType())) {
                    throw new BizIllegalArgumentException(enumMethod + "method return is not boolean type in the " + enumClass + " class");
                }
                Boolean result = (Boolean) method.invoke(null, value);
                return result != null && result;
            } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
                throw new BizIllegalArgumentException("非法的枚举值");
            } catch (SecurityException | NoSuchMethodException e) {
                throw new BizIllegalArgumentException("This " + enumMethod + "(" + valueClass + ") method does not exist in the " + enumClass);
            }
        }
    }
}
